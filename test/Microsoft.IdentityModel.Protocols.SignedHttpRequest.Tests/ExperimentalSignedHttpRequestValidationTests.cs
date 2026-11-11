// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;
using ExperimentalContext = Microsoft.IdentityModel.Protocols.SignedHttpRequest.Experimental.SignedHttpRequestValidationContext;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests;

public class ExperimentalSignedHttpRequestValidationTests
{
    public static TheoryData<string> RoundtripTheoryData
    {
        get
        {
            var data = new TheoryData<string>
            {
                "Rsa",
                "EncryptedAccessToken",
                "StringCnf",
                "RsaThumbprint",
                "SymmetricJwe"
            };
#if NET
            data.Add("Ecdsa");
#endif
            return data;
        }
    }

    [Theory, MemberData(nameof(RoundtripTheoryData))]
    public async Task Roundtrips(string scenario)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreateRoundtripContext(handler, scenario);

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.True(result.Result.IsValid);
        Assert.Null(result.Result.Exception);
        Assert.Equal(context.SignedHttpRequest, result.Result.SignedHttpRequest);
        var validatedRequest = Assert.IsType<JsonWebToken>(result.Result.ValidatedSignedHttpRequest);
        Assert.Equal(context.SignedHttpRequest, validatedRequest.EncodedToken);
        Assert.True(result.Result.AccessTokenValidationResult.Succeeded);
        var validatedAccessToken = Assert.IsType<JsonWebToken>(result.Result.AccessTokenValidationResult.Result.SecurityToken);
        string encodedAccessToken = validatedRequest.GetPayloadValue<string>(SignedHttpRequestClaimTypes.At);
        var accessToken = new JsonWebToken(encodedAccessToken);
        Assert.Equal(scenario == "EncryptedAccessToken", accessToken.IsEncrypted);
        string expectedAccessToken = accessToken.IsEncrypted
            ? new JsonWebTokenHandler().DecryptToken(accessToken, SignedHttpRequestTestUtils.DefaultTokenValidationParameters)
            : encodedAccessToken;
        Assert.Equal(expectedAccessToken, validatedAccessToken.EncodedToken);
        Assert.False(validatedAccessToken.IsEncrypted);
        Assert.Equal(Default.Issuer, validatedAccessToken.Issuer);
        Assert.Equal(new[] { Default.Audience }, validatedAccessToken.Audiences);

        if (scenario == "SymmetricJwe")
        {
            var resolvedKey = Assert.IsType<JsonWebKey>(validatedRequest.SigningKey);
            Assert.Equal(KeyingMaterial.DefaultSymmetricKeyBytes_256, Base64UrlEncoder.DecodeBytes(resolvedKey.K));
        }
        else
        {
            SecurityKey expectedKey = scenario switch
            {
#if NET
                "Ecdsa" => KeyingMaterial.Ecdsa256Key,
#endif
                _ => KeyingMaterial.RsaSecurityKey_2048
            };
            Assert.Equal(expectedKey.ComputeJwkThumbprint(), validatedRequest.SigningKey.ComputeJwkThumbprint());
        }
    }

    [Theory]
    [InlineData("Issuer", typeof(SecurityTokenInvalidIssuerException), null)]
    [InlineData("Audience", typeof(SecurityTokenInvalidAudienceException), null)]
    [InlineData("AccessTokenSignature", typeof(SecurityTokenSignatureKeyNotFoundException), null)]
    [InlineData("AccessTokenDecryption", typeof(SecurityTokenDecryptionFailedException), null)]
    [InlineData("MalformedAccessToken", typeof(SecurityTokenValidationException), "IDX14107")]
    [InlineData("ExpiredAccessToken", typeof(SecurityTokenInvalidLifetimeException), "IDX10223")]
    [InlineData("MissingCnf", typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23003")]
    [InlineData("Signature", typeof(SignedHttpRequestInvalidSignatureException), "IDX23034")]
    [InlineData("Nonce", typeof(SignedHttpRequestInvalidNonceClaimException), "nonce validation failed")]
    [InlineData("Method", typeof(SignedHttpRequestInvalidMClaimException), "IDX23011")]
    [InlineData("Host", typeof(SignedHttpRequestInvalidUClaimException), "IDX23012")]
    [InlineData("Path", typeof(SignedHttpRequestInvalidPClaimException), "IDX23011")]
    [InlineData("Query", typeof(SignedHttpRequestInvalidQClaimException), "IDX23011")]
    [InlineData("Header", typeof(SignedHttpRequestInvalidHClaimException), "IDX23011")]
    [InlineData("Body", typeof(SignedHttpRequestInvalidBClaimException), "IDX23011")]
    public async Task RequestValidationReturnsErrors(string scenario, Type exceptionType, string diagnostic)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        string accessToken = null;
        if (scenario == "MalformedAccessToken")
            accessToken = "not-a-token";

        ExperimentalContext context = CreateRoundtripContext(
            handler, scenario == "AccessTokenDecryption" ? "EncryptedAccessToken" : scenario, accessToken);
        switch (scenario)
        {
            case "Issuer":
                context.AccessTokenValidationParameters.ValidIssuers.Clear();
                context.AccessTokenValidationParameters.ValidIssuers.Add("https://wrong-issuer.example");
                break;
            case "Audience":
                context.AccessTokenValidationParameters.ValidAudiences.Clear();
                context.AccessTokenValidationParameters.ValidAudiences.Add("wrong-audience");
                break;
            case "AccessTokenSignature":
                context.AccessTokenValidationParameters.SigningKeys.Clear();
                context.AccessTokenValidationParameters.SigningKeys.Add(KeyingMaterial.RsaSecurityKey2);
                break;
            case "AccessTokenDecryption":
                context.AccessTokenValidationParameters.DecryptionKeys.Clear();
                break;
            case "Nonce":
                context.SignedHttpRequestValidationParameters.NonceValidatorAsync = (_, _, _, _) => false;
                break;
            case "Method":
                context.HttpRequestData.Method = "POST";
                break;
            case "Host":
                context.HttpRequestData.Uri = new Uri("https://other.example:8443/path?x=one&y=two");
                break;
            case "Path":
                context.HttpRequestData.Uri = new Uri("https://contoso.com:8443/other?x=one&y=two");
                break;
            case "Query":
                context.HttpRequestData.Uri = new Uri("https://contoso.com:8443/path?x=changed&y=two");
                break;
            case "Header":
                context.HttpRequestData.Headers["x-first"] = new[] { "changed" };
                break;
            case "Body":
                context.HttpRequestData.Body = Encoding.UTF8.GetBytes("changed body");
                break;
        }

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.IsType(exceptionType, error.GetException());
        if (diagnostic is not null)
            Assert.Contains(diagnostic, error.Message);

        if (scenario == "MalformedAccessToken")
            Assert.Equal(ValidationFailureType.TokenReadingFailed, error.FailureType);
        else if (scenario == "ExpiredAccessToken")
            Assert.Equal(LifetimeValidationFailure.Expired, error.FailureType);

        Assert.NotEmpty(error.StackFrames);
    }

    [Fact]
    public async Task RequestValidationPassesContextAndCancellationToDelegatesInOrder()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreateRoundtripContext(handler, "Rsa");
        using var cancellationSource = new CancellationTokenSource();
        var calls = new List<string>();
        SecurityKey expectedKey = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
        JsonWebToken resolvedRequest = null;
        context.SignedHttpRequestValidationParameters.PopKeyResolverAsync = (accessToken, request, receivedContext, cancellationToken) =>
        {
            Assert.Equal(Default.Issuer, Assert.IsType<JsonWebToken>(accessToken).Issuer);
            resolvedRequest = Assert.IsType<JsonWebToken>(request);
            Assert.Equal(context.SignedHttpRequest, resolvedRequest.EncodedToken);
            Assert.Same(context, receivedContext);
            Assert.Equal(cancellationSource.Token, cancellationToken);
            calls.Add("pop");
            return Task.FromResult(expectedKey);
        };
        context.SignedHttpRequestValidationParameters.SignatureValidatorAsync = (key, request, receivedContext, cancellationToken) =>
        {
            Assert.Same(expectedKey, key);
            Assert.Same(resolvedRequest, request);
            Assert.Same(context, receivedContext);
            Assert.Equal(cancellationSource.Token, cancellationToken);
            calls.Add("signature");
            return Task.FromResult(key);
        };
        context.SignedHttpRequestValidationParameters.NonceValidatorAsync = (key, request, receivedContext, cancellationToken) =>
        {
            Assert.Same(expectedKey, key);
            Assert.Same(resolvedRequest, request);
            Assert.Same(context, receivedContext);
            Assert.Equal(cancellationSource.Token, cancellationToken);
            calls.Add("nonce");
            return true;
        };
        context.SignedHttpRequestValidationParameters.ReplayValidatorAsync = (request, receivedContext, cancellationToken) =>
        {
            Assert.Same(resolvedRequest, request);
            Assert.Same(context, receivedContext);
            Assert.Equal(cancellationSource.Token, cancellationToken);
            calls.Add("replay");
            return Task.CompletedTask;
        };

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, cancellationSource.Token);

        // Assert
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.Equal(new[] { "pop", "signature", "nonce", "replay" }, calls);
        Assert.Same(resolvedRequest, result.Result.ValidatedSignedHttpRequest);
        Assert.Same(expectedKey, resolvedRequest.SigningKey);
    }

    [Fact]
    public async Task SignedHttpRequestReplayValidationReturnsError()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext firstContext = CreateRoundtripContext(handler, "Rsa");
        ExperimentalContext secondContext = CreateRoundtripContext(handler, "Rsa");
        var nonceCache = new HashSet<string>();
        var replayException = new InvalidOperationException("Replay detected.");
        firstContext.SignedHttpRequestValidationParameters.ReplayValidatorAsync = (request, _, _) =>
        {
            string nonce = Assert.IsType<JsonWebToken>(request).GetPayloadValue<string>(SignedHttpRequestClaimTypes.Nonce);
            return nonceCache.Add(nonce) ? Task.CompletedTask : Task.FromException(replayException);
        };
        secondContext.SignedHttpRequestValidationParameters.ReplayValidatorAsync =
            firstContext.SignedHttpRequestValidationParameters.ReplayValidatorAsync;

        // Act
        var firstResult = await handler.ValidateSignedHttpRequestAsync(firstContext, CancellationToken.None);
        var secondResult = await handler.ValidateSignedHttpRequestAsync(secondContext, CancellationToken.None);
        var replayResult = await handler.ValidateSignedHttpRequestAsync(firstContext, CancellationToken.None);

        // Assert
        Assert.True(firstResult.Succeeded, firstResult.Error?.Message);
        Assert.True(secondResult.Succeeded, secondResult.Error?.Message);
        ValidationError error = GetError(replayResult);
        Assert.Contains("IDX23039", error.Message);
        Assert.Same(replayException, error.InnerException);
        Assert.Same(replayException, error.GetException().InnerException);
        Assert.Equal(2, nonceCache.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task JkuResolutionReturnsMatchingKey(bool multipleKeys)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreateRoundtripContext(handler, "Rsa");
        JObject expectedJwk = SignedHttpRequestTestUtils.DefaultJwk;
        JObject otherJwk = SignedHttpRequestTestUtils.DefaultJwk;
        otherJwk["n"] = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters2.Modulus);
        otherJwk["kid"] = "other-key";
        var keys = multipleKeys ? new JArray(otherJwk, expectedJwk) : new JArray(expectedJwk);
        using var httpClient = HttpResponseMessageUtils.SetupHttpClientThatReturns(new JObject { ["keys"] = keys }.ToString());
        context.SignedHttpRequestValidationParameters.AllowResolvingPopKeyFromJku = true;
        context.SignedHttpRequestValidationParameters.AllowedDomainsForJkuRetrieval.Add("contoso.com");
        context.SignedHttpRequestValidationParameters.HttpClientProvider = () => httpClient;
        var cnf = new Cnf { Kid = multipleKeys ? expectedJwk["kid"].ToString() : null };

        // Act
        var result = await handler.ResolvePopKeyFromJkuAsync("https://contoso.com/keys", cnf, context, CancellationToken.None);

        // Assert
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.Equal(expectedJwk["kid"].ToString(), result.Result.KeyId);
        Assert.Equal(KeyingMaterial.RsaSecurityKey_2048.ComputeJwkThumbprint(), result.Result.ComputeJwkThumbprint());
    }

    [Theory]
    [InlineData("RequestContext", "signedHttpRequestValidationContext")]
    [InlineData("NullAccessToken", "accessToken")]
    [InlineData("EmptyAccessToken", "accessToken")]
    [InlineData("SignatureKey", "popKey")]
    [InlineData("ResolverContext", "signedHttpRequestValidationContext")]
    [InlineData("ValidatedAccessToken", "validatedAccessToken")]
    [InlineData("ConfirmationClaim", "cnf")]
    [InlineData("JsonWebKey", "jsonWebKey")]
    [InlineData("NullJku", "jkuSetUrl")]
    [InlineData("EmptyJku", "jkuSetUrl")]
    [InlineData("NullJwe", "jwe")]
    [InlineData("ReadContext", "signedHttpRequestValidationContext")]
    [InlineData("PayloadToken", "signedHttpRequest")]
    [InlineData("PayloadContext", "signedHttpRequestValidationContext")]
    public async Task NullArgumentsReturnValidationErrors(string scenario, string parameterName)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
            new HttpRequestData(),
            new ValidationParameters());

        // Act
        ValidationError error = scenario switch
        {
            "RequestContext" => GetError(await handler.ValidateSignedHttpRequestAsync((ExperimentalContext)null, CancellationToken.None)),
            "NullAccessToken" => GetError(await handler.ValidateAccessTokenAsync(null, context, CancellationToken.None)),
            "EmptyAccessToken" => GetError(await handler.ValidateAccessTokenAsync(string.Empty, context, CancellationToken.None)),
            "SignatureKey" => GetError(await handler.ValidateSignatureAsync(null, null, context, CancellationToken.None)),
            "ResolverContext" => GetError(await handler.ResolvePopKeyAsync(null, null, (ExperimentalContext)null, CancellationToken.None)),
            "ValidatedAccessToken" => GetError(handler.GetCnfClaimValue(null, null, context)),
            "ConfirmationClaim" => GetError(await handler.ResolvePopKeyFromCnfClaimAsync(null, null, null, context, CancellationToken.None)),
            "JsonWebKey" => GetError(handler.ResolvePopKeyFromJwk(null, context)),
            "NullJku" => GetError(await handler.GetPopKeysFromJkuAsync(null, context, CancellationToken.None)),
            "EmptyJku" => GetError(await handler.GetPopKeysFromJkuAsync(string.Empty, context, CancellationToken.None)),
            "NullJwe" => GetError(await handler.ResolvePopKeyFromJweAsync(null, context, CancellationToken.None)),
            "ReadContext" => GetError(handler.ReadSignedHttpRequest((ExperimentalContext)null)),
            "PayloadToken" => GetError(await handler.ValidateSignedHttpRequestPayloadAsync(null, context, CancellationToken.None)),
            "PayloadContext" => GetError(await handler.ValidateSignedHttpRequestPayloadAsync(new JsonWebToken(CreateToken("{}")), (ExperimentalContext)null, CancellationToken.None)),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };

        // Assert
        Assert.Equal(ValidationFailureType.NullArgument, error.FailureType);
        Assert.Contains(parameterName, error.Message);
        Assert.NotEmpty(error.StackFrames);
    }

    [Fact]
    public async Task ValidateAccessTokenReturnsErrorForHandlerWithoutResultBasedValidation()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var tokenHandler = new Mock<TokenHandler>(MockBehavior.Strict);
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
            new HttpRequestData(),
            new ValidationParameters());
        context.SignedHttpRequestValidationParameters.TokenHandler = tokenHandler.Object;

        // Act
        var result = await handler.ValidateAccessTokenAsync(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Equal(Experimental.SignedHttpRequestValidationFailure.ValidationFailed, error.FailureType);
        Assert.IsType<SignedHttpRequestValidationException>(error.GetException());
        Assert.Contains("IDX10267", error.Message);
        Assert.Contains(nameof(IResultBasedValidation.ValidateTokenAsync), error.Message);
        Assert.Contains(tokenHandler.Object.GetType().FullName, error.Message);
        Assert.NotEmpty(error.StackFrames);
        tokenHandler.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ResolvePopKeyPropagatesNullAccessTokenError()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
            new HttpRequestData(),
            new ValidationParameters());

        // Act
        var result = await handler.ResolvePopKeyAsync(null, null, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Equal(ValidationFailureType.NullArgument, error.FailureType);
        Assert.Contains("validatedAccessToken", error.Message);
        Assert.Equal(2, error.StackFrames.Count);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"at\":\"\"}")]
    public async Task MissingAccessTokenReturnsValidationError(string payload)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext(CreateToken(payload), new HttpRequestData(), new ValidationParameters());

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23003", error.Message);
        Assert.IsType<SignedHttpRequestInvalidAtClaimException>(error.GetException());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public void ReadSignedHttpRequestHonorsMaximumTokenSize(int sizeOffset)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        int maximumTokenSize = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        string request = CreateToken("{}").PadRight(maximumTokenSize + sizeOffset, 'a');
        var context = new ExperimentalContext(request, new HttpRequestData(), new ValidationParameters());

        // Act
        var result = handler.ReadSignedHttpRequest(context);

        // Assert
        if (sizeOffset <= 0)
        {
            Assert.True(result.Succeeded, result.Error?.Message);
            Assert.Equal(request, result.Result.EncodedToken);
        }
        else
        {
            ValidationError error = GetError(result);
            Assert.Equal(ValidationFailureType.SecurityTokenTooLarge, error.FailureType);
            Assert.Contains("IDX10209", error.Message);
            Assert.IsType<SecurityTokenValidationException>(error.GetException());
            Assert.Null(error.InnerException);
            Assert.NotEmpty(error.StackFrames);
        }
    }

    [Fact]
    public async Task MalformedRequestPropagatesTokenReadingError()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext("not-a-token", new HttpRequestData(), new ValidationParameters());

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Equal(ValidationFailureType.TokenReadingFailed, error.FailureType);
        Assert.NotNull(error.InnerException);
        Assert.Equal(3, error.StackFrames.Count);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"cnf\":\"\"}")]
    [InlineData("{\"cnf\":\"not-json\"}")]
    public void MissingOrMalformedConfirmationClaimReturnsValidationError(string payload)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var accessToken = new JsonWebToken(CreateToken(payload));

        // Act
        var result = handler.GetCnfClaimValue(null, accessToken, (ExperimentalContext)null);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23003", error.Message);
        Assert.IsType<SignedHttpRequestInvalidCnfClaimException>(error.GetException());
    }

    [Theory]
    [InlineData("UnsupportedCnf", "IDX23014", typeof(SignedHttpRequestInvalidCnfClaimException))]
    [InlineData("SymmetricJwk", "IDX23015", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("InvalidJwk", "IDX23016", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("JkuDisabled", "IDX23037", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("JkuDisallowed", "IDX23038", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("NonHttpsJku", "IDX23006", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("MissingKid", "IDX23023", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("ThumbprintMismatch", "IDX23033", typeof(SignedHttpRequestInvalidPopKeyException))]
    public async Task PopKeyFailuresReturnValidationErrors(string scenario, string diagnostic, Type exceptionType)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, new HttpRequestData(), new ValidationParameters());
        context.SignedHttpRequestValidationParameters.AllowResolvingPopKeyFromJku = scenario != "JkuDisabled";

        // Act
        ValidationError error = scenario switch
        {
            "UnsupportedCnf" => GetError(await handler.ResolvePopKeyFromCnfClaimAsync(new Cnf(), null, null, context, CancellationToken.None)),
            "SymmetricJwk" => GetError(handler.ResolvePopKeyFromJwk(new JsonWebKey(SignedHttpRequestTestUtils.DefaultJwe.ToString()), context)),
            "InvalidJwk" => GetError(handler.ResolvePopKeyFromJwk(new JsonWebKey { Kty = "unsupported" }, context)),
            "JkuDisabled" or "JkuDisallowed" => GetError(await handler.ResolvePopKeyFromJkuAsync("https://contoso.com/keys", new Cnf(), context, CancellationToken.None)),
            "NonHttpsJku" => GetError(await handler.GetPopKeysFromJkuAsync("http://contoso.com/keys", context, CancellationToken.None)),
            "MissingKid" => GetError(await handler.ResolvePopKeyFromKeyIdentifierAsync("missing", null, null, context, CancellationToken.None)),
            "ThumbprintMismatch" => GetError(await handler.ResolvePopKeyFromCnfReferenceAsync("mismatch", SignedHttpRequestTestUtils.CnfJwk, null, context, CancellationToken.None)),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };

        // Assert
        Assert.Contains(diagnostic, error.Message);
        Assert.IsType(exceptionType, error.GetException());
        Assert.NotEmpty(error.StackFrames);
    }

    [Theory]
    [InlineData("Handler", "jwtTokenHandler")]
    [InlineData("Context", "signedHttpRequestValidationContext")]
    [InlineData("NullJwe", "jwe")]
    [InlineData("EmptyJwe", "jwe")]
    public async Task DecryptSymmetricPopKeyNullArgumentsReturnErrors(string scenario, string parameterName)
    {
        // Arrange
        var context = new ExperimentalContext("request", new HttpRequestData(), new ValidationParameters());
        var handler = new JsonWebTokenHandler();
        string jwe = SignedHttpRequestTestUtils.DefaultCnfJwe[ConfirmationClaimTypes.Jwe].ToString();

        // Act
        var result = await SignedHttpRequestUtilities.DecryptSymmetricPopKeyAsync(
            scenario == "Handler" ? null : handler,
            scenario == "NullJwe" ? null : scenario == "EmptyJwe" ? string.Empty : jwe,
            scenario == "Context" ? null : context,
            CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Equal(ValidationFailureType.NullArgument, error.FailureType);
        Assert.Contains(parameterName, error.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DecryptSymmetricPopKeyReturnsKey(bool useResolver)
    {
        // Arrange
        var context = new ExperimentalContext("request", new HttpRequestData(), new ValidationParameters());
        string jwe = SignedHttpRequestTestUtils.DefaultCnfJwe[ConfirmationClaimTypes.Jwe].ToString();
        var keys = new[] { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key };
        using var cancellationSource = new CancellationTokenSource();
        bool resolverCalled = false;
        if (useResolver)
            context.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync = (token, cancellationToken) =>
            {
                Assert.Equal(jwe, Assert.IsType<JsonWebToken>(token).EncodedToken);
                Assert.Equal(cancellationSource.Token, cancellationToken);
                resolverCalled = true;
                return Task.FromResult<IEnumerable<SecurityKey>>(keys);
            };
        else
            context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = keys;

        // Act
        var result = await SignedHttpRequestUtilities.DecryptSymmetricPopKeyAsync(new JsonWebTokenHandler(), jwe, context, cancellationSource.Token);

        // Assert
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.Equal(useResolver, resolverCalled);
        Assert.Equal(JsonWebAlgorithmsKeyTypes.Octet, result.Result.Kty);
        Assert.Equal(KeyingMaterial.DefaultSymmetricKeyBytes_256, Base64UrlEncoder.DecodeBytes(result.Result.K));
    }

    [Theory]
    [InlineData("Malformed", "IDX14107")]
    [InlineData("NullKeys", "IDX23017")]
    [InlineData("EmptyKeys", "IDX23017")]
    [InlineData("WrongKey", "IDX10603")]
    [InlineData("InvalidJson", "IDX23018")]
    [InlineData("ResolverThrows", "IDX23018")]
    [InlineData("ResolverCanceled", "IDX23018")]
    [InlineData("EnumerationThrows", "IDX23018")]
    public async Task DecryptSymmetricPopKeyFailuresReturnErrors(string scenario, string diagnostic)
    {
        // Arrange
        var context = new ExperimentalContext("request", new HttpRequestData(), new ValidationParameters());
        string jwe = scenario == "Malformed" ? "not-a-jwe" :
            SignedHttpRequestTestUtils.EncryptToken(scenario == "InvalidJson" ? "not-json" : SignedHttpRequestTestUtils.DefaultJwe.ToString());
        var exception = scenario == "ResolverCanceled"
            ? (Exception)new OperationCanceledException("Resolver canceled.")
            : new InvalidOperationException("Key resolution failed.");
        context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = new[] { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key };
        switch (scenario)
        {
            case "NullKeys":
                context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = null;
                break;
            case "EmptyKeys":
                context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = Array.Empty<SecurityKey>();
                break;
            case "WrongKey":
                context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = new[] { new SymmetricSecurityKey(new byte[32]) };
                break;
            case "ResolverThrows":
            case "ResolverCanceled":
                context.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync = (_, _) =>
                    Task.FromException<IEnumerable<SecurityKey>>(exception);
                break;
            case "EnumerationThrows":
                context.SignedHttpRequestValidationParameters.CnfDecryptionKeys =
                    new[] { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }.Select<SecurityKey, SecurityKey>(_ => throw exception);
                break;
        }

        // Act
        var result = await SignedHttpRequestUtilities.DecryptSymmetricPopKeyAsync(new JsonWebTokenHandler(), jwe, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains(diagnostic, error.Message);
        Assert.NotEmpty(error.StackFrames);
        if (scenario == "WrongKey")
        {
            Assert.Equal(ValidationFailureType.TokenDecryptionFailed, error.FailureType);
            Assert.IsType<SecurityTokenDecryptionFailedException>(error.GetException());
        }
        else if (scenario != "Malformed")
        {
            Assert.IsType<SignedHttpRequestInvalidPopKeyException>(error.GetException());
        }

        if (scenario is "ResolverThrows" or "ResolverCanceled" or "EnumerationThrows")
            Assert.Same(exception, error.InnerException);

        if (scenario == "Malformed")
        {
            var resolutionResult = await new SignedHttpRequestHandler().ResolvePopKeyFromJweAsync(jwe, context, CancellationToken.None);
            Assert.Equal(error.FailureType, GetError(resolutionResult).FailureType);
            Assert.Equal(error.Message, resolutionResult.Error.Message);
        }
    }

    [Theory]
    [InlineData(0, null, "IDX23031")]
    [InlineData(2, null, "IDX23035")]
    [InlineData(2, "missing", "IDX23021")]
    public async Task JkuKeySelectionFailuresReturnValidationErrors(int keyCount, string kid, string diagnostic)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        string keys = string.Join(",", Enumerable.Repeat(SignedHttpRequestTestUtils.DefaultJwk.ToString(), keyCount));
        using var httpClient = HttpResponseMessageUtils.SetupHttpClientThatReturns("{\"keys\":[" + keys + "]}");
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, new HttpRequestData(), new ValidationParameters());
        context.SignedHttpRequestValidationParameters.AllowResolvingPopKeyFromJku = true;
        context.SignedHttpRequestValidationParameters.AllowedDomainsForJkuRetrieval.Add("contoso.com");
        context.SignedHttpRequestValidationParameters.HttpClientProvider = () => httpClient;

        // Act
        var result = await handler.ResolvePopKeyFromJkuAsync("https://contoso.com/keys", new Cnf { Kid = kid }, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains(diagnostic, error.Message);
        Assert.IsType<SignedHttpRequestInvalidPopKeyException>(error.GetException());
    }

    [Theory]
    [InlineData("Signature", "IDX23009", typeof(SignedHttpRequestInvalidSignatureException))]
    [InlineData("PopKey", "IDX23040", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("KeyId", "IDX23040", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("HttpClient", "IDX23022", typeof(SignedHttpRequestInvalidPopKeyException))]
    [InlineData("Nonce", "IDX23036", typeof(SignedHttpRequestInvalidNonceClaimException))]
    public async Task DelegateExceptionsReturnValidationErrors(string scenario, string diagnostic, Type exceptionType)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var exception = new InvalidOperationException("Delegate failed.");
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, new HttpRequestData(), new ValidationParameters());
        var parameters = context.SignedHttpRequestValidationParameters;
        parameters.SignatureValidatorAsync = (_, _, _, _) => Task.FromException<SecurityKey>(exception);
        parameters.PopKeyResolverAsync = (_, _, _, _) => Task.FromException<SecurityKey>(exception);
        parameters.PopKeyResolverFromKeyIdAsync = (_, _, _, _, _) => Task.FromException<SecurityKey>(exception);
        parameters.HttpClientProvider = () => throw exception;
        parameters.NonceValidatorAsync = (_, _, _, _) => throw exception;

        // Act
        ValidationError error = scenario switch
        {
            "Signature" => GetError(await handler.ValidateSignatureAsync(null, null, context, CancellationToken.None)),
            "PopKey" => GetError(await handler.ResolvePopKeyAsync(null, null, context, CancellationToken.None)),
            "KeyId" => GetError(await handler.ResolvePopKeyFromKeyIdentifierAsync("kid", null, null, context, CancellationToken.None)),
            "HttpClient" => GetError(await handler.GetPopKeysFromJkuAsync("https://contoso.com/keys", context, CancellationToken.None)),
            "Nonce" => GetError(handler.ValidateNonceAsync(null, null, context, CancellationToken.None)),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };

        // Assert
        Assert.Contains(diagnostic, error.Message);
        Assert.Same(exception, error.InnerException);
        Assert.IsType(exceptionType, error.GetException());
        Assert.Same(exception, error.GetException().InnerException);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [InlineData(null)]
    public void NonceValidationReturnsDelegateOutcome(bool? accepted)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, new HttpRequestData(), new ValidationParameters());
        if (accepted.HasValue)
            context.SignedHttpRequestValidationParameters.NonceValidatorAsync = (_, _, _, _) => accepted.Value;

        // Act
        var result = handler.ValidateNonceAsync(null, null, context, CancellationToken.None);

        // Assert
        if (accepted == false)
        {
            ValidationError error = GetError(result);
            Assert.Contains("nonce validation failed", error.Message);
            Assert.IsType<SignedHttpRequestInvalidNonceClaimException>(error.GetException());
        }
        else
        {
            Assert.True(result.Succeeded);
            Assert.True(result.Result);
        }
    }

    [Fact]
    public async Task UnsupportedSignatureAlgorithmReturnsValidationError()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken("{}"));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData(), new ValidationParameters());

        // Act
        var result = await handler.ValidateSignatureAsync(token, KeyingMaterial.RsaSecurityKey_2048, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23034", error.Message);
        Assert.IsType<SignedHttpRequestInvalidSignatureException>(error.GetException());
    }

    [Fact]
    public async Task RequestValidationPropagatesReadError()
    {
        // Arrange
        ValidationError expectedError = ValidationError.NullParameter("reader", ValidationError.GetCurrentStackFrame());
        var handler = new FailedReadHandler(expectedError);
        var context = new ExperimentalContext(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, new HttpRequestData(), new ValidationParameters());

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Same(expectedError, error);
        Assert.Equal(2, error.StackFrames.Count);
    }

    [Fact]
    public async Task PayloadValidationReturnsOriginalTokenAfterReplayAndAllClaims()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var token = new JsonWebToken(context.SignedHttpRequest);
        using var cancellationSource = new CancellationTokenSource();
        int replayCalls = 0;
        context.SignedHttpRequestValidationParameters.ReplayValidatorAsync = (request, receivedContext, cancellationToken) =>
        {
            Assert.Same(token, request);
            Assert.Same(context, receivedContext);
            Assert.Same(context.CallContext, receivedContext.CallContext);
            Assert.Equal(cancellationSource.Token, cancellationToken);
            replayCalls++;
            return Task.CompletedTask;
        };

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(token, context, cancellationSource.Token);

        // Assert
        Assert.True(result.Succeeded);
        Assert.Same(token, result.Result);
        Assert.Equal(1, replayCalls);
    }

    [Theory]
    [InlineData("ts", typeof(SignedHttpRequestInvalidTsClaimException))]
    [InlineData("m", typeof(SignedHttpRequestInvalidMClaimException))]
    [InlineData("u", typeof(SignedHttpRequestInvalidUClaimException))]
    [InlineData("p", typeof(SignedHttpRequestInvalidPClaimException))]
    [InlineData("q", typeof(SignedHttpRequestInvalidQClaimException))]
    [InlineData("h", typeof(SignedHttpRequestInvalidHClaimException))]
    [InlineData("b", typeof(SignedHttpRequestInvalidBClaimException))]
    public async Task PayloadClaimFailuresReturnValidationErrors(string claim, Type exceptionType)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(Base64UrlEncoder.Decode(new JsonWebToken(context.SignedHttpRequest).EncodedPayload));
        payload.Remove(claim);

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(new JsonWebToken(CreateToken(JsonSerializer.Serialize(payload))), context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23003", error.Message);
        Assert.IsType(exceptionType, error.GetException());
        Assert.Equal(2, error.StackFrames.Count);
    }

    [Theory]
    [InlineData("ts", typeof(SignedHttpRequestInvalidTsClaimException), "IDX23010")]
    [InlineData("m", typeof(SignedHttpRequestInvalidMClaimException), "IDX23011")]
    [InlineData("u", typeof(SignedHttpRequestInvalidUClaimException), "IDX23012")]
    [InlineData("p", typeof(SignedHttpRequestInvalidPClaimException), "IDX23011")]
    [InlineData("q", typeof(SignedHttpRequestInvalidQClaimException), "IDX23011")]
    [InlineData("h", typeof(SignedHttpRequestInvalidHClaimException), "IDX23011")]
    [InlineData("b", typeof(SignedHttpRequestInvalidBClaimException), "IDX23011")]
    public async Task PayloadClaimMismatchesReturnValidationErrors(string claim, Type exceptionType, string diagnostic)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(Base64UrlEncoder.Decode(new JsonWebToken(context.SignedHttpRequest).EncodedPayload));
        payload[claim] = claim switch
        {
            "ts" => 0L,
            "q" => new object[] { new[] { "x", "y" }, "wrong-hash" },
            "h" => new object[] { new[] { "x-first", "x-second" }, "wrong-hash" },
            _ => "mismatch"
        };

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(new JsonWebToken(CreateToken(JsonSerializer.Serialize(payload))), context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains(diagnostic, error.Message);
        Assert.IsType(exceptionType, error.GetException());
    }

    [Theory]
    [InlineData(false, false, false, true)]
    [InlineData(true, true, true, false)]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, true, true)]
    [InlineData(true, true, false, true)]
    public async Task PayloadValidationHonorsClaimSelection(bool validatePresent, bool includeInList, bool present, bool succeeds)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken(present ? "{\"m\":\"POST\"}" : "{}"));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData { Method = "GET" }, new ValidationParameters());
        var parameters = context.SignedHttpRequestValidationParameters;
        parameters.ValidateTs = parameters.ValidateM = parameters.ValidateU = parameters.ValidateP = false;
        parameters.ValidatePresentClaims = validatePresent;
        parameters.ClaimsToValidateWhenPresent = includeInList ? new[] { "m" } : null;

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(token, context, CancellationToken.None);

        // Assert
        if (succeeds)
        {
            Assert.True(result.Succeeded);
            Assert.Same(token, result.Result);
        }
        else
        {
            Assert.IsType<SignedHttpRequestInvalidMClaimException>(GetError(result).GetException());
        }
    }

    [Theory]
    [InlineData("q", "[]", "IDX23024")]
    [InlineData("q", "[[1],\"hash\"]", "IDX23024")]
    [InlineData("q", "[[\"missing\"],\"hash\"]", "IDX23028")]
    [InlineData("h", "[]", "IDX23024")]
    [InlineData("h", "[[null],\"hash\"]", "IDX23024")]
    [InlineData("h", "[[\"missing\"],\"hash\"]", "IDX23027")]
    public async Task PayloadHashClaimFailuresReturnValidationErrors(string claim, string value, string diagnostic)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(Base64UrlEncoder.Decode(new JsonWebToken(context.SignedHttpRequest).EncodedPayload));
        payload[claim] = JsonSerializer.Deserialize<JsonElement>(value);

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(new JsonWebToken(CreateToken(JsonSerializer.Serialize(payload))), context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains(diagnostic, error.Message);
        Assert.IsType(claim == "q" ? typeof(SignedHttpRequestInvalidQClaimException) : typeof(SignedHttpRequestInvalidHClaimException), error.GetException());
    }

    [Theory]
    [InlineData("q", false)]
    [InlineData("q", true)]
    [InlineData("h", false)]
    [InlineData("h", true)]
    public async Task PayloadValidationHonorsUnsignedComponents(string claim, bool acceptUnsigned)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var token = new JsonWebToken(context.SignedHttpRequest);
        if (claim == "q")
            context.HttpRequestData.Uri = new Uri(context.HttpRequestData.Uri + "&extra=value");
        else
            context.HttpRequestData.Headers.Add("x-extra", new[] { "value" });

        context.SignedHttpRequestValidationParameters.AcceptUnsignedQueryParameters = acceptUnsigned;
        context.SignedHttpRequestValidationParameters.AcceptUnsignedHeaders = acceptUnsigned;

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(token, context, CancellationToken.None);

        // Assert
        if (acceptUnsigned)
        {
            Assert.True(result.Succeeded);
            Assert.Same(token, result.Result);
        }
        else
        {
            ValidationError error = GetError(result);
            Assert.Contains(claim == "q" ? "IDX23029" : "IDX23026", error.Message);
        }
    }

    [Theory]
    [InlineData("path/foo%2fbar/", true, true)]
    [InlineData("/PATH/foo%2Fbar", true, false)]
    [InlineData("/PATH/foo%2fbar", false, true)]
    [InlineData("/path/foo/bar", true, false)]
    public void ExperimentalPathValidationPreservesComparisonRules(string path, bool caseSensitive, bool succeeds)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken(JsonSerializer.Serialize(new { p = path })));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData { Uri = new Uri("https://contoso.com/path/foo%2Fbar") }, new ValidationParameters());
        context.SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparison = caseSensitive;

        // Act
        var result = handler.ValidatePClaim(token, context);

        // Assert
        Assert.Equal(succeeds, result.Succeeded);
        if (!succeeds)
            Assert.IsType<SignedHttpRequestInvalidPClaimException>(GetError(result).GetException());
    }

    [Fact]
    public async Task PayloadReplayFailurePrecedesClaimValidation()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken("{}"));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData(), new ValidationParameters());
        var exception = new InvalidOperationException("Replay detected.");
        context.SignedHttpRequestValidationParameters.ReplayValidatorAsync = (_, _, _) => Task.FromException(exception);

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(token, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23039", error.Message);
        Assert.Same(exception, error.InnerException);
    }

    [Theory]
    [InlineData(long.MaxValue, 1)]
    [InlineData(0, long.MaxValue)]
    [InlineData(253402300799, 10000000)]
    public void TimestampOverflowReturnsValidationError(long timestamp, long lifetimeTicks)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken(JsonSerializer.Serialize(new { ts = timestamp })));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData(), new ValidationParameters());
        context.SignedHttpRequestValidationParameters.SignedHttpRequestLifetime = TimeSpan.FromTicks(lifetimeTicks);

        // Act
        var result = handler.ValidateTsClaim(token, context);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23041", error.Message);
        Assert.IsType<SignedHttpRequestInvalidTsClaimException>(error.GetException());
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void TimestampExpirationAtDateTimeLimitSucceeds(long offsetTicks)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        var token = new JsonWebToken(CreateToken("{\"ts\":253402300799}"));
        var context = new ExperimentalContext(token.EncodedToken, new HttpRequestData(), new ValidationParameters());
        context.SignedHttpRequestValidationParameters.SignedHttpRequestLifetime =
            DateTime.MaxValue - EpochTime.DateTime(253402300799) + TimeSpan.FromTicks(offsetTicks);

        // Act
        var result = handler.ValidateTsClaim(token, context);

        // Assert
        Assert.True(result.Succeeded);
        Assert.True(result.Result);
    }

    [Theory]
    [InlineData("p", "/path?x=one&y=two", true)]
    [InlineData("q", "/path?x=one&y=two", true)]
    [InlineData("p", "//", false)]
    [InlineData("q", "//", false)]
    public void RelativeRequestUriValidationReturnsResult(string claim, string uri, bool succeeds)
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var token = new JsonWebToken(context.SignedHttpRequest);
        context.HttpRequestData.Uri = new Uri(uri, UriKind.Relative);

        // Act
        var result = claim == "p" ? handler.ValidatePClaim(token, context) : handler.ValidateQClaim(token, context);

        // Assert
        if (succeeds)
        {
            Assert.True(result.Succeeded);
            Assert.True(result.Result);
        }
        else
        {
            ValidationError error = GetError(result);
            Assert.Contains("IDX23007", error.Message);
            Assert.IsType<SignedHttpRequestCreationException>(error.GetException());
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public async Task HeaderSanitizationFailureReturnsValidationError()
    {
        // Arrange
        var handler = new SignedHttpRequestHandler();
        ExperimentalContext context = CreatePayloadContext(handler);
        var token = new JsonWebToken(context.SignedHttpRequest);
        context.HttpRequestData.Headers.Add("x-invalid", null);

        // Act
        var result = await handler.ValidateSignedHttpRequestPayloadAsync(token, context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23025", error.Message);
        Assert.IsType<SignedHttpRequestInvalidHClaimException>(error.GetException());
        Assert.IsType<ArgumentNullException>(error.InnerException);
    }

    [Fact]
    public async Task RequestValidationPropagatesPayloadFailure()
    {
        // Arrange
        var handler = new ValidAccessTokenHandler();
        var context = new ExperimentalContext(CreateToken("{\"at\":\"access-token\"}"), new HttpRequestData(), new ValidationParameters());
        context.SignedHttpRequestValidationParameters.PopKeyResolverAsync = (_, _, _, _) => Task.FromResult<SecurityKey>(KeyingMaterial.RsaSecurityKey_2048);
        context.SignedHttpRequestValidationParameters.SignatureValidatorAsync = (key, _, _, _) => Task.FromResult(key);

        // Act
        var result = await handler.ValidateSignedHttpRequestAsync(context, CancellationToken.None);

        // Assert
        ValidationError error = GetError(result);
        Assert.Contains("IDX23003", error.Message);
        Assert.IsType<SignedHttpRequestInvalidTsClaimException>(error.GetException());
        Assert.Equal(3, error.StackFrames.Count);
    }

    private static ExperimentalContext CreateRoundtripContext(SignedHttpRequestHandler handler, string scenario, string accessToken = null)
    {
        SigningCredentials signingCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials;
        JObject cnf = SignedHttpRequestTestUtils.DefaultCnfJwk;
        string requestCnf = null;
        switch (scenario)
        {
            case "RsaThumbprint":
                cnf = SignedHttpRequestTestUtils.DefaultCnfJwkThumprint;
                requestCnf = SignedHttpRequestTestUtils.DefaultCnfJwk.ToString();
                break;
            case "SymmetricJwe":
                signingCredentials = new SigningCredentials(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256);
                cnf = SignedHttpRequestTestUtils.DefaultCnfJwe;
                break;
#if NET
            case "Ecdsa":
                signingCredentials = new SigningCredentials(KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdsaSha256);
                cnf = SignedHttpRequestTestUtils.DefaultCnfJwkEcdsa;
                break;
#endif
            case "Signature":
                cnf[JwtHeaderParameterNames.Jwk]["n"] = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters2.Modulus);
                break;
        }

        var requestData = new HttpRequestData
        {
            Method = "GET",
            Uri = new Uri("https://contoso.com:8443/path?x=one&y=two"),
            Body = Encoding.UTF8.GetBytes("request body")
        };
        requestData.Headers.Add("x-first", new[] { "one" });
        requestData.Headers.Add("x-second", new[] { "two" });
        if (accessToken is null)
        {
            JObject payload = SignedHttpRequestTestUtils.DefaultAccessTokenPayload;
            DateTime now = DateTime.UtcNow;
            payload["iat"] = EpochTime.GetIntDate(now.AddHours(-3));
            payload["nbf"] = EpochTime.GetIntDate(now.AddHours(-3));
            payload["exp"] = EpochTime.GetIntDate(now.AddHours(scenario == "ExpiredAccessToken" ? -2 : 1));
            if (scenario != "MissingCnf")
                payload["cnf"] = scenario == "StringCnf" ? new JValue(cnf.ToString()) : cnf;

            var tokenHandler = new JsonWebTokenHandler();
            accessToken = scenario == "EncryptedAccessToken"
                ? tokenHandler.CreateToken(payload.ToString(), SignedHttpRequestTestUtils.DefaultSigningCredentials, SignedHttpRequestTestUtils.DefaultEncryptingCredentials)
                : tokenHandler.CreateToken(payload.ToString(), SignedHttpRequestTestUtils.DefaultSigningCredentials);
        }

        var descriptor = new SignedHttpRequestDescriptor(
            accessToken,
            requestData,
            signingCredentials,
            new SignedHttpRequestCreationParameters { CreateQ = true, CreateH = true, CreateB = true, CreateCnf = scenario != "SymmetricJwe" })
        {
            CnfClaimValue = requestCnf
        };
        var validationParameters = new ValidationParameters();
        validationParameters.SigningKeys.Add(KeyingMaterial.RsaSigningCreds_2048_Public.Key);
        validationParameters.ValidIssuers.Add(Default.Issuer);
        validationParameters.ValidAudiences.Add(Default.Audience);
        validationParameters.DecryptionKeys.Add(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key);
        var context = new ExperimentalContext(handler.CreateSignedHttpRequest(descriptor), requestData, validationParameters);
        context.SignedHttpRequestValidationParameters.ValidateQ = true;
        context.SignedHttpRequestValidationParameters.ValidateH = true;
        context.SignedHttpRequestValidationParameters.ValidateB = true;
        context.SignedHttpRequestValidationParameters.CnfDecryptionKeys = new[] { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key };
        return context;
    }

    private static ExperimentalContext CreatePayloadContext(SignedHttpRequestHandler handler)
    {
        var requestData = new HttpRequestData
        {
            Method = "GET",
            Uri = new Uri("https://contoso.com:8443/path?x=one&y=two"),
            Body = Encoding.UTF8.GetBytes("request body")
        };
        requestData.Headers.Add("x-first", new[] { "one" });
        requestData.Headers.Add("x-second", new[] { "two" });
        var descriptor = new SignedHttpRequestDescriptor(
            SignedHttpRequestTestUtils.DefaultEncodedAccessToken, requestData,
            new SigningCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256),
            new SignedHttpRequestCreationParameters { CreateQ = true, CreateH = true, CreateB = true });
        string payload = handler.CreateHttpRequestPayload(descriptor, new CallContext());
        var context = new ExperimentalContext(CreateToken(payload), requestData, new ValidationParameters());
        context.SignedHttpRequestValidationParameters.ValidateQ = true;
        context.SignedHttpRequestValidationParameters.ValidateH = true;
        context.SignedHttpRequestValidationParameters.ValidateB = true;
        return context;
    }

    private sealed class ValidAccessTokenHandler : SignedHttpRequestHandler
    {
        internal override Task<ValidationResult<ValidatedToken, ValidationError>> ValidateAccessTokenAsync(string accessToken, ExperimentalContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return Task.FromResult<ValidationResult<ValidatedToken, ValidationError>>(
                new ValidatedToken(new JsonWebToken(CreateToken("{}")), new JsonWebTokenHandler(), signedHttpRequestValidationContext.AccessTokenValidationParameters));
        }
    }

    private static string CreateToken(string payload)
    {
        return Base64UrlEncoder.Encode("{\"alg\":\"none\"}") + "." + Base64UrlEncoder.Encode(payload) + ".";
    }

    private sealed class FailedReadHandler : SignedHttpRequestHandler
    {
        private readonly ValidationError _error;

        internal FailedReadHandler(ValidationError error)
        {
            _error = error;
        }

        internal override ValidationResult<JsonWebToken, ValidationError> ReadSignedHttpRequest(ExperimentalContext signedHttpRequestValidationContext)
        {
            return _error;
        }
    }

    private static ValidationError GetError<TResult>(ValidationResult<TResult, ValidationError> result)
    {
        Assert.False(result.Succeeded);
        Assert.NotNull(result.Error);
        return result.Error;
    }
}
