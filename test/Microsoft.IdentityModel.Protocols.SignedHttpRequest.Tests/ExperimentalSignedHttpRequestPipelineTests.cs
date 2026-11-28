// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Context = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationContext;
using Policy = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationParameters;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public partial class ExperimentalSignedHttpRequestPipelineTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero);

        private sealed class FixedTime : TimeProvider
        {
            public override DateTimeOffset GetUtcNow() => Now;
        }

        private sealed class RecordingTokenHandler : TokenHandler
        {
            internal Func<string, ValidationParameters, CallContext, CancellationToken, Task<ValidationResult<ValidatedToken, ValidationError>>> OnValidate;
            internal override Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
                string token, ValidationParameters parameters, CallContext context, CancellationToken cancellationToken)
                => OnValidate(token, parameters, context, cancellationToken);
        }

        private static ValidationParameters Parameters()
        {
            var parameters = new ValidationParameters { TimeProvider = new FixedTime() };
            parameters.SigningKeys.Add(SignedHttpRequestTestUtils.DefaultSigningCredentials.Key);
            parameters.ValidIssuers.Add(Default.Issuer);
            parameters.ValidAudiences.Add(Default.Audience);
            parameters.DecryptionKeys.Add(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key);
            return parameters;
        }

        private static string AccessToken(JToken cnf = null, bool encrypt = false, bool omitCnf = false)
        {
            var payload = SignedHttpRequestTestUtils.DefaultAccessTokenPayload;
            payload["iat"] = EpochTime.GetIntDate(Now.UtcDateTime);
            payload["nbf"] = EpochTime.GetIntDate(Now.UtcDateTime.AddMinutes(-1));
            payload["exp"] = EpochTime.GetIntDate(Now.UtcDateTime.AddHours(1));
            if (!omitCnf)
                payload["cnf"] = cnf ?? SignedHttpRequestTestUtils.DefaultCnfJwk;
            var token = new JsonWebTokenHandler().CreateToken(payload.ToString(Formatting.None), SignedHttpRequestTestUtils.DefaultSigningCredentials);
            return encrypt ? SignedHttpRequestTestUtils.EncryptToken(token) : token;
        }

        private static JObject Payload(string accessToken = null) => new JObject
        {
            ["at"] = accessToken ?? AccessToken(),
            ["ts"] = EpochTime.GetIntDate(Now.UtcDateTime),
            ["m"] = "GET",
            ["u"] = "www.contoso.com",
            ["p"] = "/path1",
            ["q"] = new JArray(new JArray("a", "b"), Hash("a=one&b=two")),
            ["h"] = new JArray(new JArray("x-first", "x-second"), Hash("x-first: one\nx-second: two")),
            ["b"] = Hash("body")
        };

        private static string Hash(string value) => SignedHttpRequestTestUtils.CalculateBase64UrlEncodedHash(value);

        private static HttpRequestData Request() => new HttpRequestData
        {
            Method = "GET",
            Uri = new Uri("https://www.contoso.com/path1?a=one&b=two"),
            Body = Encoding.UTF8.GetBytes("body"),
            Headers = new Dictionary<string, IEnumerable<string>>
            {
                ["x-first"] = new[] { "one" },
                ["x-second"] = new[] { "two" }
            }
        };

        private static Policy AllClaims() => new Policy { ValidateQ = true, ValidateH = true, ValidateB = true };

        private static Context CreateContext(JObject payload = null, Policy policy = null, HttpRequestData request = null,
            CallContext callContext = null, SigningCredentials credentials = null)
        {
            string token = new JsonWebTokenHandler().CreateToken((payload ?? Payload()).ToString(Formatting.None),
                credentials ?? SignedHttpRequestTestUtils.DefaultSigningCredentials);
            return new Context(token, request ?? Request(), new TokenValidationParameters(), policy ?? AllClaims(), callContext ?? new CallContext());
        }

        private static Task<ValidationResult<ValidatedSignedHttpRequest, ValidationError>> Validate(
            Context context, ValidationParameters parameters = null, CancellationToken cancellation = default)
            => new SignedHttpRequestHandler().ValidateSignedHttpRequestAsync(context, parameters ?? Parameters(), cancellation);

        private static SignedHttpRequestValidationError Error(ValidationResult<ValidatedSignedHttpRequest, ValidationError> result,
            SignedHttpRequestValidationFailure stage, string claim = null)
        {
            Assert.False(result.Succeeded);
            var error = Assert.IsType<SignedHttpRequestValidationError>(result.Error);
            Assert.Same(stage, error.FailureType);
            Assert.Equal(claim, error.ClaimName);
            return error;
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task RealSignatureValidatesOuterAndEmbeddedAccessToken(bool encryptedAccessToken)
        {
            // Arrange
            var context = CreateContext(Payload(AccessToken(encrypt: encryptedAccessToken)));
            var parameters = Parameters();
            // Act
            var result = await Validate(context, parameters: parameters);
            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Equal(context.SignedHttpRequest, result.Result.SignedHttpRequest);
            Assert.Equal("GET", result.Result.ValidatedToken.GetPayloadValue<string>("m"));
            Assert.Equal("Bob@contoso.com", result.Result.AccessTokenValidationResult.ClaimsIdentity.FindFirst("email").Value);
            Assert.Same(parameters, result.Result.AccessTokenValidationResult.ValidationParameters);
            Assert.Equal(Default.Issuer, ((JsonWebToken)result.Result.AccessTokenValidationResult.SecurityToken).Issuer);
            Assert.Equal(SignedHttpRequestTestUtils.CnfJwk.JsonWebKey.ComputeJwkThumbprint(), result.Result.ValidatedToken.SigningKey.ComputeJwkThumbprint());
        }

        [Fact]
        public async Task EmbeddedAccessTokenReceivesOriginalArgumentsAndReturnsOriginalArtifact()
        {
            // Arrange
            var parameters = Parameters();
            var callContext = new CallContext();
            using var cancellation = new CancellationTokenSource();
            string at = AccessToken();
            var validated = await new JsonWebTokenHandler().ValidateTokenAsync(at, parameters, callContext, cancellation.Token);
            Assert.True(validated.Succeeded, validated.Error?.Message);
            int calls = 0;
            var handler = new RecordingTokenHandler
            {
                OnValidate = (token, p, c, ct) =>
                {
                    Assert.Equal(at, token);
                    Assert.Same(parameters, p);
                    Assert.Same(callContext, c);
                    Assert.Equal(cancellation.Token, ct);
                    calls++;
                    return Task.FromResult(validated);
                }
            };
            var policy = AllClaims();
            policy.TokenHandler = handler;
            // Act
            var result = await Validate(CreateContext(Payload(at), policy, callContext: callContext), parameters, cancellation.Token);
            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Same(validated.Result, result.Result.AccessTokenValidationResult);
            Assert.Equal(1, calls);
        }

        [Theory, MemberData(nameof(InvalidOuterTokenTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task InvalidOuterTokenIsRejectedBeforeAccessTokenValidation(ExperimentalPipelineTheoryData theoryData)
        {
            // Arrange
            var policy = AllClaims();
            var handler = new Mock<TokenHandler>(MockBehavior.Strict);
            policy.TokenHandler = handler.Object;
            // Act
            var result = await Validate(new Context(theoryData.SignedHttpRequest, Request(), new TokenValidationParameters(), policy));
            // Assert
            AssertPipelineOutcome(result, theoryData);
            handler.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task AccessTokenFailureRetainsNestedErrorAndLazyLegacyException()
        {
            // Arrange
            var nested = ValidationError.NullParameter("nested-at", ValidationError.GetCurrentStackFrame());
            var handler = new RecordingTokenHandler
            {
                OnValidate = (t, p, c, ct) =>
                Task.FromResult(new ValidationResult<ValidatedToken, ValidationError>(nested))
            };
            var policy = AllClaims();
            policy.TokenHandler = handler;
            // Act
            var result = await Validate(CreateContext(policy: policy));
            // Assert
            var error = Error(result, SignedHttpRequestValidationFailure.AccessToken, "at");
            Assert.Same(nested, error.InnerValidationError);
            var exception = Assert.IsType<SignedHttpRequestInvalidAtClaimException>(error.GetException());
            Assert.Same(nested.GetException(), exception.InnerException);
            Assert.Same(exception, error.GetException());
        }

        [Theory]
        [InlineData("ts")]
        [InlineData("m")]
        [InlineData("u")]
        [InlineData("p")]
        [InlineData("q")]
        [InlineData("h")]
        [InlineData("b")]
        public async Task RequiredClaimsRejectMissingAndMismatchedValues(string claim)
        {
            foreach (bool missing in new[] { true, false })
            {
                // Arrange
                var payload = Payload();
                if (missing)
                    payload.Remove(claim);
                else
                    payload[claim] = claim == "ts" ? new JValue(0) : new JValue("wrong");
                // Act
                var result = await Validate(CreateContext(payload));
                // Assert
                var error = Error(result, SignedHttpRequestValidationFailure.Claim, claim);
                Assert.Equal("SignedHttpRequestInvalid" + claim.ToUpperInvariant()[0] + claim.Substring(1) + "ClaimException", error.GetException().GetType().Name);
            }
        }

        [Theory]
        [InlineData("ts")]
        [InlineData("m")]
        [InlineData("u")]
        [InlineData("p")]
        [InlineData("q")]
        [InlineData("h")]
        [InlineData("b")]
        public async Task OptionalClaimPolicyValidatesOnlyConfiguredPresentClaims(string claim)
        {
            // Arrange
            var policy = new Policy
            {
                ValidateTs = false,
                ValidateM = false,
                ValidateU = false,
                ValidateP = false,
                ValidatePresentClaims = true,
                ClaimsToValidateWhenPresent = new[] { claim }
            };
            var payload = Payload();
            payload[claim] = "wrong";
            // Act / Assert
            Error(await Validate(CreateContext(payload, policy)), SignedHttpRequestValidationFailure.Claim, claim);
            payload.Remove(claim);
            Assert.True((await Validate(CreateContext(payload, policy))).Succeeded);
            payload[claim] = "wrong";
            policy.ValidatePresentClaims = false;
            Assert.True((await Validate(CreateContext(payload, policy))).Succeeded);
            policy.ValidatePresentClaims = true;
            policy.ClaimsToValidateWhenPresent = Array.Empty<string>();
            Assert.True((await Validate(CreateContext(payload, policy))).Succeeded);
        }

        [Theory]
        [InlineData(-301, false)]
        [InlineData(-300, true)]
        [InlineData(-299, true)]
        [InlineData(3600, true)]
        public async Task TimestampUsesConfiguredTimeProviderAndInclusiveExpiry(int offsetSeconds, bool succeeds)
        {
            // Arrange
            var payload = Payload();
            payload["ts"] = EpochTime.GetIntDate(Now.UtcDateTime.AddSeconds(offsetSeconds));
            // Act
            var result = await Validate(CreateContext(payload));
            // Assert
            Assert.Equal(succeeds, result.Succeeded);
            if (!succeeds)
                Assert.IsType<SignedHttpRequestInvalidTsClaimException>(Error(result, SignedHttpRequestValidationFailure.Claim, "ts").GetException());
        }

        [Theory]
        [InlineData("m", " get ", "https://www.contoso.com/path1", true)]
        [InlineData("u", "WWW.CONTOSO.COM:443", "https://www.contoso.com/path1", true)]
        [InlineData("u", "www.contoso.com:444", "https://www.contoso.com/path1", false)]
        [InlineData("p", "/a%2fb", "https://www.contoso.com/a%2Fb", true)]
        [InlineData("p", "/A%2fb", "https://www.contoso.com/a%2Fb", false)]
        [InlineData("p", "///path1///", "https://www.contoso.com/path1", true)]
        public async Task MethodHostAndPathPreserveLegacyComparisonRules(string claim, string value, string uri, bool succeeds)
        {
            // Arrange
            var payload = Payload();
            payload[claim] = value;
            var request = Request();
            request.Uri = new Uri(uri + "?a=one&b=two");
            // Act
            var result = await Validate(CreateContext(payload, request: request));
            // Assert
            Assert.Equal(succeeds, result.Succeeded);
            if (!succeeds)
                Error(result, SignedHttpRequestValidationFailure.Claim, claim);
        }

        [Theory]
        [InlineData("q")]
        [InlineData("h")]
        public async Task HashClaimsRejectMalformedStructureAndDuplicateOrMissingNames(string claim)
        {
            foreach (string json in new[] { "null", "{}", "[]", "[[]]", "[[],\"hash\",0]", "[\"names\",\"hash\"]",
                "[[],123]", "[[123],\"hash\"]", "[[null],\"hash\"]", "[[\"absent\"],\"hash\"]",
                claim == "q" ? "[[\"a\",\"a\"],\"hash\"]" : "[[\"x-first\",\"x-first\"],\"hash\"]" })
            {
                // Arrange
                var payload = Payload();
                payload[claim] = JToken.Parse(json);
                // Act
                var result = await Validate(CreateContext(payload));
                // Assert
                Error(result, SignedHttpRequestValidationFailure.Claim, claim);
            }
        }

        [Theory]
        [InlineData("q", true)]
        [InlineData("q", false)]
        [InlineData("h", true)]
        [InlineData("h", false)]
        public async Task HashClaimsHonorDeclaredOrderAndUnsignedLeftoverPolicy(string claim, bool acceptUnsigned)
        {
            // Arrange
            var payload = Payload();
            var policy = AllClaims();
            policy.AcceptUnsignedQueryParameters = acceptUnsigned;
            policy.AcceptUnsignedHeaders = acceptUnsigned;
            var names = claim == "q" ? new JArray("b", "a") : new JArray("x-second", "x-first");
            string reversed = claim == "q" ? "b=two&a=one" : "x-second: two\nx-first: one";
            payload[claim] = new JArray(names, Hash(reversed));
            // Act / Assert
            Assert.True((await Validate(CreateContext(payload, policy))).Succeeded);
            payload[claim][1] = Hash(claim == "q" ? "a=one&b=two" : "x-first: one\nx-second: two");
            Error(await Validate(CreateContext(payload, policy)), SignedHttpRequestValidationFailure.Claim, claim);
            payload[claim] = claim == "q" ? new JArray(new JArray("a"), Hash("a=one")) : new JArray(new JArray("x-first"), Hash("x-first: one"));
            Assert.Equal(acceptUnsigned, (await Validate(CreateContext(payload, policy))).Succeeded);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task BodyHashBindsExactBytesAndTreatsNullAsEmpty(bool nullBody)
        {
            // Arrange
            var payload = Payload();
            var request = Request();
            request.Body = nullBody ? null : Array.Empty<byte>();
            payload["b"] = Hash("");
            // Act / Assert
            Assert.True((await Validate(CreateContext(payload, request: request))).Succeeded);
            request.Body = Encoding.UTF8.GetBytes("Body");
            Error(await Validate(CreateContext(payload, request: request)), SignedHttpRequestValidationFailure.Claim, "b");
        }

        private static Task<ValidationResult<T, ValidationError>> CallbackResult<T>(CallbackOutcome outcome, T success, ValidationError error,
            Exception exception, CancellationTokenSource cancellation)
        {
            if (outcome == CallbackOutcome.Throw)
                throw exception;
            if (outcome == CallbackOutcome.UnrequestedCancellation)
                throw new OperationCanceledException("unrequested");
            if (outcome == CallbackOutcome.Cancel)
            {
                cancellation.Cancel();
                throw new OperationCanceledException(cancellation.Token);
            }
            if (outcome == CallbackOutcome.CancelThenReturn)
                cancellation.Cancel();
            if (outcome == CallbackOutcome.NullTask)
                return null;
            return Task.FromResult(outcome == CallbackOutcome.NullResult ? new ValidationResult<T, ValidationError>(default(T)) :
                outcome == CallbackOutcome.Error ? new ValidationResult<T, ValidationError>(error) :
                outcome == CallbackOutcome.Default ? default : new ValidationResult<T, ValidationError>(success));
        }

        [Theory]
        [MemberData(nameof(CallbackCases), DisableDiscoveryEnumeration = true)]
        public async Task CallbackResultsArePropagatedOrClassifiedAndRequestedCancellationEscapes(ExperimentalCallbackTheoryData theoryData)
        {
            // Arrange
            using var cancellation = new CancellationTokenSource();
            var fixture = new CallbackFixture(theoryData.Outcome, cancellation);
            theoryData.Configure(fixture);
            var context = CreateContext(fixture.Payload, fixture.Policy, callContext: theoryData.CallContext,
                credentials: fixture.SigningCredentials);
            fixture.Context = context;
            var outcome = theoryData.Outcome;
            bool accessTokenCallback = theoryData.Stage == SignedHttpRequestValidationFailure.AccessToken;
            // Act / Assert
            if (outcome == CallbackOutcome.Cancel || outcome == CallbackOutcome.CancelThenReturn)
            {
                var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Validate(context, fixture.Parameters, cancellation.Token));
                Assert.Equal(cancellation.Token, exception.CancellationToken);
            }
            else
            {
                var result = await Validate(context, fixture.Parameters, cancellation.Token);
                if (outcome == CallbackOutcome.Success)
                {
                    Assert.True(result.Succeeded, result.Error?.Message);
                    Assert.Equal(context.SignedHttpRequest, result.Result.SignedHttpRequest);
                    if (theoryData.Stage == SignedHttpRequestValidationFailure.Signature)
                        Assert.Same(fixture.Key, result.Result.ValidatedToken.SigningKey);
                }
                else if (outcome == CallbackOutcome.Error && !accessTokenCallback)
                {
                    Assert.False(result.Succeeded);
                    Assert.Same(fixture.NestedError, result.Error);
                }
                else
                {
                    var error = Error(result, theoryData.Stage, accessTokenCallback ? "at" : null);
                    if (outcome == CallbackOutcome.Error)
                        Assert.Same(fixture.NestedError, error.InnerValidationError);
                    else
                    {
                        var classified = accessTokenCallback ? Assert.IsType<SignedHttpRequestValidationError>(error.InnerValidationError) : error;
                        if (outcome == CallbackOutcome.Throw)
                            Assert.Same(fixture.ThrownException, classified.GetException().InnerException);
                        if (outcome == CallbackOutcome.UnrequestedCancellation)
                            Assert.IsType<OperationCanceledException>(classified.GetException().InnerException);
                        if (outcome == CallbackOutcome.Default || outcome == CallbackOutcome.NullResult)
                            Assert.Contains("IDX23041", classified.Message);
                        if (outcome == CallbackOutcome.NullTask)
                            Assert.IsType<NullReferenceException>(classified.GetException().InnerException);
                    }
                }
            }
            Assert.Equal(1, fixture.Calls);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task FalseNonceOrReplayStopsPipelineBeforeBindings(bool rejectNonce)
        {
            // Arrange
            var policy = AllClaims();
            var payload = Payload();
            payload["ts"] = 0;
            var order = new List<string>();
            var nonce = new Mock<INonceValidator>();
            nonce.Setup(x => x.ValidateNonceAsync(It.IsAny<SecurityKey>(), It.IsAny<SecurityToken>(), It.IsAny<Context>(), It.IsAny<CancellationToken>()))
                .Returns(() => { order.Add("nonce"); return Task.FromResult(new ValidationResult<bool, ValidationError>(!rejectNonce)); });
            var replay = new Mock<IReplayValidator>();
            replay.Setup(x => x.ValidateReplayAsync(It.IsAny<SecurityToken>(), It.IsAny<Context>(), It.IsAny<CancellationToken>()))
                .Returns(() => { order.Add("replay"); return Task.FromResult(new ValidationResult<bool, ValidationError>(false)); });
            policy.NonceValidator = nonce.Object;
            policy.ReplayValidator = replay.Object;
            // Act
            var result = await Validate(CreateContext(payload, policy));
            // Assert
            var error = Error(result, rejectNonce ? SignedHttpRequestValidationFailure.Nonce : SignedHttpRequestValidationFailure.Replay,
                rejectNonce ? "nonce" : null);
            Assert.Equal(rejectNonce ? ["nonce"] : ["nonce", "replay"], order);
            Assert.Equal(rejectNonce ? typeof(SignedHttpRequestInvalidNonceClaimException) : typeof(SignedHttpRequestValidationException), error.GetException().GetType());
        }

        [Fact]
        public async Task PreCanceledRequestDoesNotInvokeAccessTokenHandler()
        {
            // Arrange
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            var handler = new Mock<TokenHandler>(MockBehavior.Strict);
            var policy = AllClaims();
            policy.TokenHandler = handler.Object;
            // Act / Assert
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Validate(CreateContext(policy: policy), cancellation: cancellation.Token));
            handler.VerifyNoOtherCalls();
        }

        [Theory, MemberData(nameof(DefaultConfirmationTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task DefaultConfirmationRejectsMissingMalformedOrNonAsymmetricKeys(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
        }

        [Theory, MemberData(nameof(KidThumbprintTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task KidThumbprintReferenceMatchesOuterKeyAndGuardsRecursion(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
            {
                Assert.Equal(SignedHttpRequestTestUtils.CnfJwk.JsonWebKey.ComputeJwkThumbprint(), result.Result.ValidatedToken.SigningKey.ComputeJwkThumbprint());
            }
        }

        [Theory, MemberData(nameof(EncryptedConfirmationTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task EncryptedConfirmationDecryptsRawSymmetricJwkOnly(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
            {
                Assert.Equal(((SymmetricSecurityKey)theoryData.SigningCredentials.Key).Key,
                    Base64UrlEncoder.DecodeBytes(Assert.IsType<JsonWebKey>(result.Result.ValidatedToken.SigningKey).K));
            }
            if (theoryData.ExpectedInnerFailure != null)
                Assert.Same(theoryData.ExpectedInnerFailure,
                    Assert.IsType<SignedHttpRequestValidationError>(result.Error).InnerValidationError.FailureType);
        }

        private sealed class FakeJkuHandler : HttpMessageHandler
        {
            internal string Json;
            internal HttpStatusCode Status = HttpStatusCode.OK;
            internal int Calls;
            internal Uri RequestedUri;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Calls++;
                RequestedUri = request.RequestUri;
                return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Json) });
            }
        }

        [Theory, MemberData(nameof(JkuTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task JkuUsesOnlyAllowedHostsAndSelectsKeyWithoutNetwork(ExperimentalJkuTheoryData theoryData)
        {
            // Arrange
            var fake = new FakeJkuHandler
            {
                Json = theoryData.Json,
                Status = theoryData.Status
            };
            using var client = new HttpClient(fake);
            var policy = AllClaims();
            policy.AllowResolvingPopKeyFromJku = theoryData.AllowResolving;
            policy.RequireHttpsForJkuResourceRetrieval = theoryData.RequireHttps;
            foreach (string domain in theoryData.AllowedDomains)
                policy.AllowedDomainsForJkuRetrieval.Add(domain);
            policy.HttpClientProvider = theoryData.HttpClientProvider ?? (() => client);
            var cnf = new JObject { ["jku"] = theoryData.Url };
            if (theoryData.Kid != null)
                cnf["kid"] = theoryData.Kid;
            // Act
            var result = await Validate(CreateContext(Payload(AccessToken(cnf)), policy));
            // Assert
            AssertPipelineOutcome(result, theoryData);
            Assert.Equal(theoryData.ExpectedHttpCalls, fake.Calls);
            if (theoryData.ExpectedHttpCalls != 0)
                Assert.Equal(new Uri(theoryData.Url), fake.RequestedUri);
            if (result.Succeeded)
                Assert.Equal(SignedHttpRequestTestUtils.CnfJwk.JsonWebKey.ComputeJwkThumbprint(), result.Result.ValidatedToken.SigningKey.ComputeJwkThumbprint());
        }

        [Theory, MemberData(nameof(SignatureProviderTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task SignatureVerificationReleasesProviderOnSuccessFailureAndException(ExperimentalSignatureTheoryData theoryData)
        {
            // Arrange: return a unique key so no shared fixture crypto factory is mutated.
            var key = new RsaSecurityKey(KeyingMaterial.RsaParameters_2048);
            var factory = new Mock<CryptoProviderFactory>(MockBehavior.Strict);
            var thrown = new InvalidOperationException("verify-sentinel");
            var tracking = new TrackingSignatureProvider(key, theoryData.Verifies, theoryData.Throws ? thrown : null);
            factory.Setup(x => x.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256, key)).Returns(theoryData.Supported);
            if (theoryData.Supported)
            {
                factory.Setup(x => x.CreateForVerifying(key, SecurityAlgorithms.RsaSha256, false))
                    .Returns(theoryData.ReturnsProvider ? tracking : null);
                if (theoryData.ReturnsProvider)
                    factory.Setup(x => x.ReleaseSignatureProvider(tracking));
            }
            key.CryptoProviderFactory = factory.Object;
            var pop = new Mock<IPopKeyResolver>();
            pop.Setup(x => x.ResolvePopKeyAsync(It.IsAny<SecurityToken>(), It.IsAny<SecurityToken>(), It.IsAny<Context>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ValidationResult<SecurityKey, ValidationError>(key));
            var policy = AllClaims();
            policy.PopKeyResolver = pop.Object;
            // Act
            var result = await Validate(CreateContext(policy: policy));
            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
                Assert.Same(key, result.Result.ValidatedToken.SigningKey);
            else
            {
                var error = Error(result, SignedHttpRequestValidationFailure.Signature);
                Assert.IsType<SignedHttpRequestInvalidSignatureException>(error.GetException());
                if (theoryData.Throws)
                    Assert.Same(thrown, error.GetException().InnerException);
            }
            Assert.Equal(theoryData.Supported && theoryData.ReturnsProvider ? 1 : 0, tracking.Verifications);
            if (theoryData.Supported && theoryData.ReturnsProvider)
                factory.Verify(x => x.ReleaseSignatureProvider(tracking), Times.Once);
            factory.VerifyAll();
            factory.VerifyNoOtherCalls();
        }

        private sealed class TrackingSignatureProvider : SignatureProvider
        {
            private readonly bool _verifies;
            private readonly Exception _exception;
            internal int Verifications;
            internal TrackingSignatureProvider(SecurityKey key, bool verifies, Exception exception)
                : base(key, SecurityAlgorithms.RsaSha256)
            {
                _verifies = verifies;
                _exception = exception;
            }
            public override byte[] Sign(byte[] input) => throw new NotSupportedException();
            public override bool Verify(byte[] input, byte[] signature) => Check();
            public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength) => Check();
            private bool Check()
            {
                Verifications++;
                if (_exception != null)
                    throw _exception;
                return _verifies;
            }
            protected override void Dispose(bool disposing) { }
        }

        [Fact]
        public async Task RealSignatureRejectsTamperedPayload()
        {
            // Arrange: change an otherwise unchecked payload field without re-signing.
            var context = CreateContext();
            string[] segments = context.SignedHttpRequest.Split('.');
            var payload = JObject.Parse(Base64UrlEncoder.Decode(segments[1]));
            payload["sentinel"] = "tampered";
            segments[1] = Base64UrlEncoder.Encode(payload.ToString(Formatting.None));
            // Act
            var result = await Validate(new Context(string.Join(".", segments), Request(), new TokenValidationParameters(), AllClaims()));
            // Assert
            Assert.IsType<SignedHttpRequestInvalidSignatureException>(Error(result, SignedHttpRequestValidationFailure.Signature).GetException());
        }

        [Theory]
        [InlineData("q")]
        [InlineData("h")]
        public async Task RepeatedRequestNamesCannotBeCoveredByHash(string claim)
        {
            // Arrange
            var request = Request();
            if (claim == "q")
                request.Uri = new Uri("https://www.contoso.com/path1?a=one&a=other&b=two");
            else
                request.Headers["x-first"] = new[] { "one", "other" };
            var payload = Payload();
            // Act / Assert
            Error(await Validate(CreateContext(payload, request: request)), SignedHttpRequestValidationFailure.Claim, claim);
            payload[claim] = claim == "q" ? new JArray(new JArray("b"), Hash("b=two"))
                : new JArray(new JArray("x-second"), Hash("x-second: two"));
            var policy = AllClaims();
            policy.AcceptUnsignedHeaders = false;
            policy.AcceptUnsignedQueryParameters = false;
            var result = await Validate(CreateContext(payload, policy, request));
            Assert.True(result.Succeeded, result.Error?.Message);
        }

        [Theory]
        [InlineData("q")]
        [InlineData("h")]
        public async Task EmptyHashNameListBindsEmptyRequestAndRejectsNonemptyUnsignedValues(string claim)
        {
            // Arrange
            var payload = Payload();
            payload[claim] = new JArray(new JArray(), Hash(""));
            var policy = AllClaims();
            policy.AcceptUnsignedHeaders = false;
            policy.AcceptUnsignedQueryParameters = false;
            // Act / Assert
            Error(await Validate(CreateContext(payload, policy)), SignedHttpRequestValidationFailure.Claim, claim);
            var request = Request();
            if (claim == "q")
                request.Uri = new Uri("https://www.contoso.com/path1");
            else
                request.Headers.Clear();
            Assert.True((await Validate(CreateContext(payload, policy, request))).Succeeded);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task PathLiteralCaseFollowsConfiguredComparisonPolicy(bool caseSensitive)
        {
            // Arrange
            var payload = Payload();
            payload["p"] = "/PATH1";
            var policy = AllClaims();
            policy.UseCaseSensitivePClaimComparison = caseSensitive;
            // Act
            var result = await Validate(CreateContext(payload, policy));
            // Assert
            Assert.Equal(!caseSensitive, result.Succeeded);
            if (caseSensitive)
                Error(result, SignedHttpRequestValidationFailure.Claim, "p");
        }

        [Theory, MemberData(nameof(InvalidTimestampTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task TimestampRejectsInvalidShapeAndHonorsZeroLifetime(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
        }

        [Theory, MemberData(nameof(MissingBindingInputTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task MissingHttpBindingInputsReturnErrorsRatherThanThrowing(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
        }

        [Fact]
        public async Task NullValidationContextReturnsResultError()
        {
            // Act
            var result = await new SignedHttpRequestHandler().ValidateSignedHttpRequestAsync((Context)null, Parameters(), CancellationToken.None);
            // Assert
            Assert.False(result.Succeeded);
            Assert.IsType<ArgumentNullException>(result.Error.GetException());
        }

        [Theory, MemberData(nameof(AccessTokenFailureTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task RealAccessTokenValidationFailuresAreNestedInAtError(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            var error = Error(result, SignedHttpRequestValidationFailure.AccessToken, "at");
            var exception = Assert.IsType<SignedHttpRequestInvalidAtClaimException>(error.GetException());
            Assert.Same(error.InnerValidationError.GetException(), exception.InnerException);
            if (theoryData.ExpectedInnerFailure != null)
                Assert.Same(theoryData.ExpectedInnerFailure, error.InnerValidationError.FailureType);
        }

        [Fact]
        public async Task BodyBindingRejectsCaseChangesInOtherwiseIdenticalBody()
        {
            // Arrange
            var context = CreateContext();
            Assert.True((await Validate(context)).Succeeded);
            context.HttpRequestData.Body = Encoding.UTF8.GetBytes("Body");
            // Act / Assert
            Assert.IsType<SignedHttpRequestInvalidBClaimException>(
                Error(await Validate(context), SignedHttpRequestValidationFailure.Claim, "b").GetException());
        }

        [Fact]
        public async Task BindingFailuresFollowTimestampMethodHostPathQueryHeaderBodyOrder()
        {
            // Arrange
            var payload = Payload();
            var valid = Payload();
            string[] claims = { "ts", "m", "u", "p", "q", "h", "b" };
            foreach (string claim in claims)
                payload[claim] = claim == "ts" ? new JValue(0) : new JValue("wrong");
            foreach (string claim in claims)
            {
                // Act / Assert
                Error(await Validate(CreateContext(payload)), SignedHttpRequestValidationFailure.Claim, claim);
                payload[claim] = valid[claim].DeepClone();
            }
            Assert.True((await Validate(CreateContext(payload))).Succeeded);
        }

        [Fact]
        public async Task EncryptedAccessTokenWrapperResolvesConfirmationFromValidatedInnerToken()
        {
            // Arrange: custom handlers may return the decrypted wrapper rather than the inner JWS.
            string inner = AccessToken();
            string encrypted = SignedHttpRequestTestUtils.EncryptToken(inner);
            var parameters = Parameters();
            var wrapper = new JsonWebToken(encrypted);
            var validated = await new JsonWebTokenHandler().ValidateTokenAsync(wrapper, parameters, new CallContext(), CancellationToken.None);
            Assert.True(validated.Succeeded, validated.Error?.Message);
            Assert.Same(validated.Result.SecurityToken, wrapper.InnerToken);
            var handler = new RecordingTokenHandler();
            var artifact = new ValidatedToken(wrapper, handler, parameters);
            handler.OnValidate = (t, p, c, ct) =>
            {
                Assert.Equal(encrypted, t);
                return Task.FromResult(new ValidationResult<ValidatedToken, ValidationError>(artifact));
            };
            var policy = AllClaims();
            policy.TokenHandler = handler;
            // Act
            var result = await Validate(CreateContext(Payload(encrypted), policy), parameters: parameters);
            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Same(artifact, result.Result.AccessTokenValidationResult);
            Assert.Equal(SignedHttpRequestTestUtils.CnfJwk.JsonWebKey.ComputeJwkThumbprint(),
                result.Result.ValidatedToken.SigningKey.ComputeJwkThumbprint());
        }

        [Theory, MemberData(nameof(LegacyPathBindingTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task ValidatePClaimPreservesLegacyEncodingBoundaries(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
                Assert.Equal(theoryData.TokenPayload["p"].Value<string>(), result.Result.ValidatedToken.GetPayloadValue<string>("p"));
        }

        [Theory, MemberData(nameof(LegacyHashBindingTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task ValidateHashClaimsPreservesLegacyCanonicalization(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
            {
                Assert.Equal("GET", result.Result.ValidatedToken.GetPayloadValue<string>("m"));
                Assert.Equal("Bob@contoso.com", result.Result.AccessTokenValidationResult.ClaimsIdentity.FindFirst("email").Value);
            }
        }

        [Theory, MemberData(nameof(OptionalClaimListTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task ValidatePresentClaimsIgnoresNullOrUnknownClaimList(ExperimentalPipelineTheoryData theoryData)
        {
            // Act
            var result = await Validate(theoryData.BuildContext());
            // Assert
            AssertPipelineOutcome(result, theoryData);
            Assert.Equal("wrong", result.Result.ValidatedToken.GetPayloadValue<string>("m"));
        }

        [Fact]
        public async Task PopKeyResolverOverridesMissingConfirmationClaim()
        {
            // Arrange
            using var cancellation = new CancellationTokenSource();
            var key = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            var payload = Payload(AccessToken(omitCnf: true));
            var policy = AllClaims();
            var context = CreateContext(payload, policy);
            var resolver = new Mock<IPopKeyResolver>(MockBehavior.Strict);
            resolver.Setup(x => x.ResolvePopKeyAsync(
                It.Is<SecurityToken>(t => ((JsonWebToken)t).GetPayloadValue<string>("email") == "Bob@contoso.com"),
                It.Is<SecurityToken>(t => ((JsonWebToken)t).EncodedToken == context.SignedHttpRequest),
                context, cancellation.Token))
                .ReturnsAsync(new ValidationResult<SecurityKey, ValidationError>(key));
            policy.PopKeyResolver = resolver.Object;

            // Act
            var result = await Validate(context, cancellation: cancellation.Token);

            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Same(key, result.Result.ValidatedToken.SigningKey);
            Assert.False(((JsonWebToken)result.Result.AccessTokenValidationResult.SecurityToken).TryGetPayloadValue<string>("cnf", out _));
            resolver.VerifyAll();
            resolver.VerifyNoOtherCalls();
        }

        [Theory, MemberData(nameof(DecryptionKeyListTheoryData), DisableDiscoveryEnumeration = true)]
        public async Task CnfDecryptionKeysResolverOverridesConfiguredKeys(ExperimentalDecryptionKeysTheoryData theoryData)
        {
            // Arrange
            var policy = AllClaims();
            policy.CnfDecryptionKeys = theoryData.ConfiguredKeys;
            var payload = EncryptedKeyPayload(SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None));
            var credentials = SymmetricCredentials();
            var context = CreateContext(payload, policy, credentials: credentials, callContext: theoryData.CallContext);
            var resolver = new Mock<ICnfDecryptionKeysResolver>(MockBehavior.Strict);
            if (theoryData.ResolvedKeys != null)
            {
                resolver.Setup(x => x.ResolveDecryptionKeysAsync(
                    It.Is<SecurityToken>(t => ((JsonWebToken)t).IsEncrypted), context, CancellationToken.None))
                    .ReturnsAsync(new ValidationResult<IList<SecurityKey>, ValidationError>(theoryData.ResolvedKeys));
                policy.CnfDecryptionKeysResolver = resolver.Object;
            }

            // Act
            var result = await Validate(context);

            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
                Assert.Equal(((SymmetricSecurityKey)credentials.Key).Key,
                    Base64UrlEncoder.DecodeBytes(Assert.IsType<JsonWebKey>(result.Result.ValidatedToken.SigningKey).K));
            if (theoryData.ResolvedKeys != null)
                resolver.Verify(x => x.ResolveDecryptionKeysAsync(It.IsAny<SecurityToken>(), context, CancellationToken.None), Times.Once);
            resolver.VerifyNoOtherCalls();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task NonJsonAccessTokenRequiresCustomPopKeyResolver(bool customResolver)
        {
            // Arrange: custom TokenHandlers may return a different SecurityToken implementation.
            var accessToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken();
            var parameters = Parameters();
            var handler = new RecordingTokenHandler();
            var artifact = new ValidatedToken(accessToken, handler, parameters);
            handler.OnValidate = (t, p, c, ct) => Task.FromResult(new ValidationResult<ValidatedToken, ValidationError>(artifact));
            var policy = AllClaims();
            policy.TokenHandler = handler;
            var context = CreateContext(policy: policy);
            var key = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            var resolver = new Mock<IPopKeyResolver>(MockBehavior.Strict);
            if (customResolver)
            {
                resolver.Setup(x => x.ResolvePopKeyAsync(accessToken, It.IsAny<SecurityToken>(), context, CancellationToken.None))
                    .ReturnsAsync(new ValidationResult<SecurityKey, ValidationError>(key));
                policy.PopKeyResolver = resolver.Object;
            }

            // Act
            var result = await Validate(context, parameters: parameters);

            // Assert
            Assert.Equal(customResolver, result.Succeeded);
            if (customResolver)
            {
                Assert.Same(artifact, result.Result.AccessTokenValidationResult);
                Assert.Same(key, result.Result.ValidatedToken.SigningKey);
                resolver.Verify(x => x.ResolvePopKeyAsync(accessToken, It.IsAny<SecurityToken>(), context, CancellationToken.None), Times.Once);
            }
            else
                Assert.Same(ValidationFailureType.SecurityTokenNotExpectedType, result.Error.FailureType);
            resolver.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task SignatureValidatorResultDoesNotReplaceNoncePopKey()
        {
            // Arrange: distinct key instances expose accidental replacement of the resolved PoP key.
            var popKey = new RsaSecurityKey(KeyingMaterial.RsaParameters_2048);
            var signatureKey = new RsaSecurityKey(KeyingMaterial.RsaParameters_2048);
            var policy = AllClaims();
            var context = CreateContext(policy: policy);
            SecurityToken seenToken = null;
            var order = new List<string>();
            var pop = new Mock<IPopKeyResolver>(MockBehavior.Strict);
            pop.Setup(x => x.ResolvePopKeyAsync(It.IsAny<SecurityToken>(), It.IsAny<SecurityToken>(), context, CancellationToken.None))
                .Returns((SecurityToken at, SecurityToken shr, Context c, CancellationToken ct) =>
                {
                    seenToken = shr;
                    order.Add("pop");
                    return Task.FromResult(new ValidationResult<SecurityKey, ValidationError>(popKey));
                });
            var signature = new Mock<ISignedHttpRequestSignatureValidator>(MockBehavior.Strict);
            signature.Setup(x => x.ValidateSignatureAsync(popKey, It.Is<SecurityToken>(t => ReferenceEquals(t, seenToken)), context, CancellationToken.None))
                .Returns(() =>
                {
                    order.Add("signature");
                    return Task.FromResult(new ValidationResult<SecurityKey, ValidationError>(signatureKey));
                });
            var nonce = new Mock<INonceValidator>(MockBehavior.Strict);
            nonce.Setup(x => x.ValidateNonceAsync(popKey, It.Is<SecurityToken>(t => ReferenceEquals(t, seenToken)), context, CancellationToken.None))
                .Returns(() =>
                {
                    Assert.Same(signatureKey, seenToken.SigningKey);
                    order.Add("nonce");
                    return Task.FromResult(new ValidationResult<bool, ValidationError>(true));
                });
            policy.PopKeyResolver = pop.Object;
            policy.SignatureValidator = signature.Object;
            policy.NonceValidator = nonce.Object;

            // Act
            var result = await Validate(context);

            // Assert
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Same(seenToken, result.Result.ValidatedToken);
            Assert.Same(signatureKey, result.Result.ValidatedToken.SigningKey);
            Assert.Equal(["pop", "signature", "nonce"], order);
            pop.Verify(x => x.ResolvePopKeyAsync(It.IsAny<SecurityToken>(), It.IsAny<SecurityToken>(), context, CancellationToken.None), Times.Once);
            signature.Verify(x => x.ValidateSignatureAsync(popKey, It.IsAny<SecurityToken>(), context, CancellationToken.None), Times.Once);
            nonce.Verify(x => x.ValidateNonceAsync(popKey, It.IsAny<SecurityToken>(), context, CancellationToken.None), Times.Once);
            pop.VerifyNoOtherCalls();
            signature.VerifyNoOtherCalls();
            nonce.VerifyNoOtherCalls();
        }
    }
}
