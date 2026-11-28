// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Net;
using System.Net.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Context = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationContext;
using Policy = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationParameters;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public partial class ExperimentalSignedHttpRequestPipelineTests
    {
        // As in the legacy SHR theories, data carries inputs and expected exceptions, not dispatch labels.
        // ToString deliberately excludes tokens, JSON, exception text and arbitrary request data from TRX names.
        public class ExperimentalPipelineTheoryData : TheoryDataBase
        {
            public ExperimentalPipelineTheoryData(string testId) : base(testId) { }
            public JObject TokenPayload { get; set; }
            public string SignedHttpRequest { get; set; }
            public HttpRequestData HttpRequestData { get; set; }
            public Policy Policy { get; set; }
            public SigningCredentials SigningCredentials { get; set; }
            public ValidationFailureType ExpectedFailure { get; set; }
            public ValidationFailureType ExpectedInnerFailure { get; set; }
            public Type ExpectedInnerException { get; set; }
            public string ExpectedClaim { get; set; }

            public Context BuildContext() => CreateContext(TokenPayload, Policy, HttpRequestData,
                callContext: CallContext, credentials: SigningCredentials);
            public override string ToString() => TestId;
        }

        private static void AssertPipelineOutcome(ValidationResult<ValidatedSignedHttpRequest, ValidationError> result,
            ExperimentalPipelineTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader(nameof(ExperimentalSignedHttpRequestPipelineTests), theoryData);
            IdentityComparer.AreBoolsEqual(result.Succeeded, theoryData.ExpectedException.TypeExpected == null, context);
            TestUtilities.AssertFailIfErrors(context);
            if (result.Succeeded)
                theoryData.ExpectedException.ProcessNoException(context);
            else
            {
                Assert.Same(theoryData.ExpectedFailure, result.Error.FailureType);
                if (result.Error is SignedHttpRequestValidationError error)
                    Assert.Equal(theoryData.ExpectedClaim, error.ClaimName);

                // Errors are returned, not thrown by the pipeline. Inspect the lazy legacy exception directly.
                theoryData.ExpectedException.ProcessException(result.Error.GetException(), context);
                if (theoryData.ExpectedInnerException != null)
                    Assert.IsAssignableFrom(theoryData.ExpectedInnerException, result.Error.GetException().InnerException);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ExperimentalPipelineTheoryData> InvalidOuterTokenTheoryData
        {
            get
            {
                var missingAt = Payload();
                missingAt.Remove("at");
                var emptyAt = WithClaim("at", "");
                var nullAt = WithClaim("at", JValue.CreateNull());
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    new ExperimentalPipelineTheoryData("Malformed")
                    {
                        SignedHttpRequest = "not.a.jwt",
                        ExpectedFailure = ValidationFailureType.TokenReadingFailed,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenValidationException), ignoreInnerException: true)
                    },
                    new ExperimentalPipelineTheoryData("Unsigned")
                    {
                        SignedHttpRequest = new JsonWebTokenHandler().CreateToken(Payload().ToString(Formatting.None)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23043")
                    },
                    new ExperimentalPipelineTheoryData("Encrypted")
                    {
                        SignedHttpRequest = SignedHttpRequestTestUtils.EncryptToken(CreateContext().SignedHttpRequest),
                        ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23043")
                    },
                    new ExperimentalPipelineTheoryData("Oversize")
                    {
                        SignedHttpRequest = new string('x', new JsonWebTokenHandler().MaximumTokenSizeInBytes + 1),
                        ExpectedFailure = ValidationFailureType.SecurityTokenTooLarge,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenValidationException), "IDX23044")
                    },
                    new ExperimentalPipelineTheoryData("MissingAccessToken")
                    {
                        SignedHttpRequest = CreateContext(missingAt).SignedHttpRequest,
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23003")
                    },
                    new ExperimentalPipelineTheoryData("EmptyAccessToken")
                    {
                        SignedHttpRequest = CreateContext(emptyAt).SignedHttpRequest,
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23003")
                    },
                    new ExperimentalPipelineTheoryData("NullAccessToken")
                    {
                        SignedHttpRequest = CreateContext(nullAt).SignedHttpRequest,
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23003")
                    }
                };
            }
        }

        public static TheoryData<ExperimentalPipelineTheoryData> DefaultConfirmationTheoryData => new TheoryData<ExperimentalPipelineTheoryData>
        {
            new ExperimentalPipelineTheoryData("MissingCnf")
            {
                TokenPayload = Payload(AccessToken(omitCnf: true)),
                ExpectedFailure = SignedHttpRequestValidationFailure.ConfirmationClaim, ExpectedClaim = "cnf",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23003")
            },
            new ExperimentalPipelineTheoryData("MalformedCnf")
            {
                TokenPayload = Payload(AccessToken(new JValue("{invalid"))),
                ExpectedFailure = SignedHttpRequestValidationFailure.ConfirmationClaim, ExpectedClaim = "cnf",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23042", ignoreInnerException: true),
                ExpectedInnerException = typeof(System.Text.Json.JsonException)
            },
            new ExperimentalPipelineTheoryData("EmptyCnf")
            {
                TokenPayload = Payload(AccessToken(new JObject())),
                ExpectedFailure = SignedHttpRequestValidationFailure.ConfirmationClaim, ExpectedClaim = "cnf",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23014")
            },
            new ExperimentalPipelineTheoryData("PlainSymmetricJwk")
            {
                TokenPayload = Payload(AccessToken(new JObject { ["jwk"] = SignedHttpRequestTestUtils.DefaultJwe })),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23015")
            },
            new ExperimentalPipelineTheoryData("InvalidRsaJwk")
            {
                TokenPayload = Payload(AccessToken(new JObject { ["jwk"] = SignedHttpRequestTestUtils.InvalidJwk })),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23016")
            }
        };

        public static TheoryData<ExperimentalPipelineTheoryData> KidThumbprintTheoryData
        {
            get
            {
                var match = Payload(AccessToken(SignedHttpRequestTestUtils.DefaultCnfJwkThumprint));
                match["cnf"] = SignedHttpRequestTestUtils.DefaultCnfJwk;
                var mismatch = (JObject)match.DeepClone();
                mismatch["at"] = AccessToken(new JObject { ["kid"] = "wrong-thumbprint" });
                var recursive = (JObject)match.DeepClone();
                recursive["cnf"] = SignedHttpRequestTestUtils.DefaultKid;
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    new ExperimentalPipelineTheoryData("MatchingThumbprint") { TokenPayload = match },
                    new ExperimentalPipelineTheoryData("MismatchingThumbprint")
                    {
                        TokenPayload = mismatch, ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23033")
                    },
                    new ExperimentalPipelineTheoryData("RecursiveReference")
                    {
                        TokenPayload = recursive, ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23023")
                    },
                    new ExperimentalPipelineTheoryData("MissingOuterReference")
                    {
                        TokenPayload = Payload(AccessToken(SignedHttpRequestTestUtils.DefaultCnfJwkThumprint)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.ConfirmationClaim, ExpectedClaim = "cnf",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23003")
                    }
                };
            }
        }

        private static SigningCredentials SymmetricCredentials() => new SigningCredentials(
            new SymmetricSecurityKey(Base64UrlEncoder.DecodeBytes(KeyingMaterial.DefaultSymmetricKeyEncoded_256)),
            SecurityAlgorithms.HmacSha256);

        private static JObject EncryptedKeyPayload(string plaintext) => Payload(AccessToken(
            new JObject { ["jwe"] = SignedHttpRequestTestUtils.EncryptToken(plaintext) }));

        private static Policy DecryptionPolicy(SecurityKey key)
        {
            var policy = AllClaims();
            policy.CnfDecryptionKeys = new[] { key };
            return policy;
        }

        public static TheoryData<ExperimentalPipelineTheoryData> EncryptedConfirmationTheoryData => new TheoryData<ExperimentalPipelineTheoryData>
        {
            new ExperimentalPipelineTheoryData("ValidSymmetricJwk")
            {
                TokenPayload = EncryptedKeyPayload(SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None)),
                Policy = DecryptionPolicy(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key),
                SigningCredentials = SymmetricCredentials()
            },
            new ExperimentalPipelineTheoryData("NoDecryptionKey")
            {
                TokenPayload = EncryptedKeyPayload(SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None)),
                SigningCredentials = SymmetricCredentials(),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23017")
            },
            new ExperimentalPipelineTheoryData("WrongDecryptionKey")
            {
                TokenPayload = EncryptedKeyPayload(SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None)),
                Policy = DecryptionPolicy(new SymmetricSecurityKey(new byte[32])),
                SigningCredentials = SymmetricCredentials(),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedInnerFailure = ValidationFailureType.TokenDecryptionFailed,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException),
                    innerTypeExpected: typeof(SecurityTokenDecryptionFailedException))
            },
            new ExperimentalPipelineTheoryData("AsymmetricPlaintext")
            {
                TokenPayload = EncryptedKeyPayload(SignedHttpRequestTestUtils.DefaultJwk.ToString(Formatting.None)),
                Policy = DecryptionPolicy(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key),
                SigningCredentials = SymmetricCredentials(),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23019")
            },
            new ExperimentalPipelineTheoryData("MalformedPlaintext")
            {
                TokenPayload = EncryptedKeyPayload("{"),
                Policy = DecryptionPolicy(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key),
                SigningCredentials = SymmetricCredentials(),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), innerTypeExpected: typeof(ArgumentException))
            }
        };

        public class ExperimentalJkuTheoryData : ExperimentalPipelineTheoryData
        {
            public ExperimentalJkuTheoryData(string testId, string errorCode = null, Type innerException = null) : base(testId)
            {
                if (errorCode != null)
                {
                    ExpectedFailure = SignedHttpRequestValidationFailure.PopKey;
                    ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), errorCode, innerException);
                }
            }

            public string Url { get; set; } = "https://keys.contoso.com/jwks";
            public string Json { get; set; } = KeySetJson();
            public string Kid { get; set; }
            public System.Collections.Generic.IEnumerable<string> AllowedDomains { get; set; } = new[] { "keys.contoso.com" };
            public bool AllowResolving { get; set; } = true;
            public bool RequireHttps { get; set; } = true;
            public HttpClientProvider HttpClientProvider { get; set; }
            public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
            public int ExpectedHttpCalls { get; set; } = 1;
        }

        private static string KeySetJson(bool multiple = false)
        {
            var keys = new JArray(SignedHttpRequestTestUtils.DefaultJwk);
            if (multiple)
            {
                var other = SignedHttpRequestTestUtils.DefaultJwk;
                other["kid"] = "other";
                keys.Insert(0, other);
            }

            return new JObject { ["keys"] = keys }.ToString(Formatting.None);
        }

        public static TheoryData<ExperimentalJkuTheoryData> JkuTheoryData => new TheoryData<ExperimentalJkuTheoryData>
        {
            new ExperimentalJkuTheoryData("SingleKey"),
            new ExperimentalJkuTheoryData("CaseInsensitiveHostWithPathAndQuery") { Url = "https://KEYS.CONTOSO.COM/tenant/jwks?version=1" },
            new ExperimentalJkuTheoryData("MultipleKeysMatchingKid") { Json = KeySetJson(true), Kid = (string)SignedHttpRequestTestUtils.DefaultJwk["kid"] },
            new ExperimentalJkuTheoryData("LegitimateSubdomain") { Url = "https://sub.keys.contoso.com/jwks" },
            new ExperimentalJkuTheoryData("Disabled", "IDX23037") { AllowResolving = false, ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("HttpRejected", "IDX23006") { Url = "http://keys.contoso.com/jwks", ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("HttpExplicitlyAllowed") { Url = "http://keys.contoso.com/jwks", RequireHttps = false },
            new ExperimentalJkuTheoryData("LookalikeDomain", "IDX23038") { Url = "https://evilkeys.contoso.com/jwks", ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("UnlistedDomain", "IDX23038") { Url = "https://elsewhere.example/jwks", ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("NullAndEmptyAllowedDomains", "IDX23038") { AllowedDomains = new string[] { null, "" }, ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("MalformedUri", "IDX23038") { Url = ":", ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("NullHttpClient", "IDX23041") { HttpClientProvider = () => null, ExpectedHttpCalls = 0 },
            new ExperimentalJkuTheoryData("HttpProviderThrows", "IDX23039", typeof(InvalidOperationException))
            {
                HttpClientProvider = () => throw new InvalidOperationException("http-provider-sentinel"), ExpectedHttpCalls = 0
            },
            new ExperimentalJkuTheoryData("EmptyKeySet", "IDX23031") { Json = "{\"keys\":[]}" },
            new ExperimentalJkuTheoryData("MultipleKeysWithoutKid", "IDX23035") { Json = KeySetJson(true) },
            new ExperimentalJkuTheoryData("MultipleKeysMissingKid", "IDX23021") { Json = KeySetJson(true), Kid = "missing" },
            new ExperimentalJkuTheoryData("MultipleKeysKidCaseMismatch", "IDX23021") { Json = KeySetJson(true), Kid = ((string)SignedHttpRequestTestUtils.DefaultJwk["kid"]).ToUpperInvariant() },
            new ExperimentalJkuTheoryData("MalformedJson", "IDX23039", typeof(ArgumentException)) { Json = "{" },
            new ExperimentalJkuTheoryData("HttpError", "IDX23039", typeof(HttpRequestException)) { Status = HttpStatusCode.BadRequest }
        };
    }
}
