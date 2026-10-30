// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Policy = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationParameters;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public partial class ExperimentalSignedHttpRequestPipelineTests
    {
        public class ExperimentalSignatureTheoryData : ExperimentalPipelineTheoryData
        {
            public ExperimentalSignatureTheoryData(string testId) : base(testId) { }
            public bool Supported { get; set; } = true;
            public bool ReturnsProvider { get; set; } = true;
            public bool Verifies { get; set; }
            public bool Throws { get; set; }
        }

        public static TheoryData<ExperimentalSignatureTheoryData> SignatureProviderTheoryData => new TheoryData<ExperimentalSignatureTheoryData>
        {
            new ExperimentalSignatureTheoryData("Success") { Verifies = true },
            new ExperimentalSignatureTheoryData("InvalidSignature")
            {
                ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException))
            },
            new ExperimentalSignatureTheoryData("VerificationThrows")
            {
                Throws = true, ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), innerTypeExpected: typeof(InvalidOperationException))
            },
            new ExperimentalSignatureTheoryData("UnsupportedAlgorithm")
            {
                Supported = false, ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException))
            },
            new ExperimentalSignatureTheoryData("NullProvider")
            {
                ReturnsProvider = false, ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX10636")
            }
        };

        private static JObject WithClaim(string claim, JToken value)
        {
            var payload = Payload();
            payload[claim] = value;
            return payload;
        }

        public static TheoryData<ExperimentalPipelineTheoryData> InvalidTimestampTheoryData => new TheoryData<ExperimentalPipelineTheoryData>
        {
            new ExperimentalPipelineTheoryData("StringTimestamp")
            {
                TokenPayload = WithClaim("ts", "not-a-timestamp"),
                ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "ts",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23042")
            },
            new ExperimentalPipelineTheoryData("TimestampOverflow")
            {
                TokenPayload = WithClaim("ts", long.MaxValue),
                ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "ts",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23042", typeof(ArgumentOutOfRangeException))
            },
            new ExperimentalPipelineTheoryData("ZeroLifetimeExpired")
            {
                TokenPayload = WithClaim("ts", EpochTime.GetIntDate(Now.UtcDateTime.AddSeconds(-1))),
                Policy = new Policy { ValidateQ = true, ValidateH = true, ValidateB = true, SignedHttpRequestLifetime = TimeSpan.Zero },
                ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "ts",
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23010")
            },
            new ExperimentalPipelineTheoryData("ZeroLifetimeExact")
            {
                Policy = new Policy { ValidateQ = true, ValidateH = true, ValidateB = true, SignedHttpRequestLifetime = TimeSpan.Zero }
            }
        };

        public static TheoryData<ExperimentalPipelineTheoryData> MissingBindingInputTheoryData
        {
            get
            {
                var method = Request();
                method.Method = null;
                var uri = Request();
                uri.Uri = null;
                var relative = Request();
                relative.Uri = new Uri("/path1", UriKind.Relative);
                var headers = Request();
                headers.Headers["x-first"] = null;
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    new ExperimentalPipelineTheoryData("NullMethod")
                    {
                        HttpRequestData = method, ExpectedFailure = ValidationFailureType.NullArgument,
                        ExpectedException = ExpectedException.ArgumentNullException()
                    },
                    new ExperimentalPipelineTheoryData("NullUri")
                    {
                        HttpRequestData = uri, ExpectedFailure = ValidationFailureType.NullArgument,
                        ExpectedException = ExpectedException.ArgumentNullException()
                    },
                    new ExperimentalPipelineTheoryData("RelativeHost")
                    {
                        HttpRequestData = relative, ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "u",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23001")
                    },
                    new ExperimentalPipelineTheoryData("NullHeaderValue")
                    {
                        HttpRequestData = headers, ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "h",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidHClaimException), "IDX23042")
                    }
                };
            }
        }

        private static string SignAccessToken(JObject payload) => new JsonWebTokenHandler().CreateToken(
            payload.ToString(Formatting.None), SignedHttpRequestTestUtils.DefaultSigningCredentials);

        public static TheoryData<ExperimentalPipelineTheoryData> AccessTokenFailureTheoryData
        {
            get
            {
                string token = AccessToken();
                string[] segments = token.Split('.');
                var original = JObject.Parse(Base64UrlEncoder.Decode(segments[1]));
                var issuer = (JObject)original.DeepClone();
                issuer["iss"] = "https://wrong.example";
                var audience = (JObject)original.DeepClone();
                audience["aud"] = "wrong-resource";
                var lifetime = (JObject)original.DeepClone();
                lifetime["nbf"] = EpochTime.GetIntDate(Now.UtcDateTime.AddHours(-2));
                lifetime["exp"] = EpochTime.GetIntDate(Now.UtcDateTime.AddHours(-1));
                var tampered = (JObject)original.DeepClone();
                tampered["email"] = "tampered@example.com";
                segments[1] = Base64UrlEncoder.Encode(tampered.ToString(Formatting.None));
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    new ExperimentalPipelineTheoryData("InvalidIssuer")
                    {
                        TokenPayload = Payload(SignAccessToken(issuer)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException),
                            innerTypeExpected: typeof(SecurityTokenInvalidIssuerException))
                    },
                    new ExperimentalPipelineTheoryData("InvalidAudience")
                    {
                        TokenPayload = Payload(SignAccessToken(audience)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException),
                            innerTypeExpected: typeof(SecurityTokenInvalidAudienceException))
                    },
                    new ExperimentalPipelineTheoryData("ExpiredAccessToken")
                    {
                        TokenPayload = Payload(SignAccessToken(lifetime)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedInnerFailure = LifetimeValidationFailure.Expired,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException),
                            innerTypeExpected: typeof(SecurityTokenInvalidLifetimeException))
                    },
                    new ExperimentalPipelineTheoryData("TamperedAccessToken")
                    {
                        TokenPayload = Payload(string.Join(".", segments)),
                        ExpectedFailure = SignedHttpRequestValidationFailure.AccessToken, ExpectedClaim = "at",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException),
                            innerTypeExpected: typeof(SecurityTokenInvalidSignatureException))
                    }
                };
            }
        }

        private static ExperimentalPipelineTheoryData PathCase(string testId, string requestPath, string claim, bool succeeds = true)
        {
            var request = Request();
            request.Uri = new Uri("https://www.contoso.com" + requestPath + "?a=one&b=two");
            return new ExperimentalPipelineTheoryData(testId)
            {
                HttpRequestData = request,
                TokenPayload = WithClaim("p", claim),
                ExpectedFailure = succeeds ? null : SignedHttpRequestValidationFailure.Claim,
                ExpectedClaim = succeeds ? null : "p",
                ExpectedException = succeeds ? ExpectedException.NoExceptionExpected
                    : new ExpectedException(typeof(SignedHttpRequestInvalidPClaimException), "IDX23011")
            };
        }

        public static TheoryData<ExperimentalPipelineTheoryData> LegacyPathBindingTheoryData
        {
            get
            {
                var relative = PathCase("RelativeRequestPath", "/path1", "/path1");
                relative.HttpRequestData.Uri = new Uri("/path1?a=one&b=two", UriKind.Relative);
                relative.Policy = AllClaims();
                relative.Policy.ValidateU = false;
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    PathCase("EncodedSlashIsNotLiteralSlash", "/foo%2Fbar", "/foo/bar", false),
                    PathCase("LiteralSlashIsNotEncodedSlash", "/foo/bar", "/foo%2Fbar", false),
                    PathCase("DoubleEncodedIsNotSingleEncoded", "/foo%252Fbar", "/foo%2Fbar", false),
                    PathCase("DoubleEncodedSlash", "/foo%252Fbar", "/foo%252Fbar"),
                    PathCase("EncodedPercent", "/foo%25bar", "/foo%25bar"),
                    PathCase("Utf8MultipleTripletsHexCase", "/caf%C3%A9", "/caf%c3%a9"),
                    PathCase("LiteralAndHexCaseMismatch", "/Foo%2Fbar", "/foo%2fbar", false),
                    PathCase("DifferentEncodedOctet", "/foo%2Fbar", "/foo%3Fbar", false),
                    PathCase("TrailingPercent", "/foo%25", "/foo%", false),
                    PathCase("TruncatedTriplet", "/foo%252", "/foo%2", false),
                    PathCase("NonHexTriplet", "/foo%252G", "/foo%2G", false),
                    PathCase("RootSlash", "/", "/"),
                    PathCase("RootEmptyClaim", "/", ""),
                    relative
                };
            }
        }

        private static ExperimentalPipelineTheoryData HashBindingCase(string testId, string claim, JArray names,
            string hash, HttpRequestData request, bool succeeds = true, string errorCode = "IDX23011")
        {
            var policy = AllClaims();
            policy.AcceptUnsignedHeaders = false;
            policy.AcceptUnsignedQueryParameters = false;
            return new ExperimentalPipelineTheoryData(testId)
            {
                HttpRequestData = request,
                TokenPayload = WithClaim(claim, new JArray(names, hash)),
                Policy = policy,
                ExpectedFailure = succeeds ? null : SignedHttpRequestValidationFailure.Claim,
                ExpectedClaim = succeeds ? null : claim,
                ExpectedException = succeeds ? ExpectedException.NoExceptionExpected
                    : new ExpectedException(claim == "q" ? typeof(SignedHttpRequestInvalidQClaimException) : typeof(SignedHttpRequestInvalidHClaimException), errorCode)
            };
        }

        public static TheoryData<ExperimentalPipelineTheoryData> LegacyHashBindingTheoryData
        {
            get
            {
                var querySpec = Request();
                querySpec.Uri = new Uri("https://www.contoso.com/path1?b=bar&a=foo&c=duck");
                var queryNameSpace = Request();
                queryNameSpace.Uri = new Uri("https://www.contoso.com/path1?query Param1=value1");
                var queryValueSpace = Request();
                queryValueSpace.Uri = new Uri("https://www.contoso.com/path1?queryParam1=val ue1");
                var queryCase = Request();
                queryCase.Uri = new Uri("https://www.contoso.com/path1?A=one&b=two");
                var ignoredQuery = Request();
                ignoredQuery.Uri = new Uri("https://www.contoso.com/path1?a=one&empty=&bare&=value&extra=one=two&b=two");
                var headerSpec = Request();
                headerSpec.Headers = new Dictionary<string, IEnumerable<string>>
                {
                    ["Content-Type"] = new[] { "application/json" },
                    ["Etag"] = new[] { "742-3u8f34-3r2nvv3" }
                };
                var authorization = Request();
                authorization.Headers["aUtHoRiZaTiOn"] = new[] { "Bearer ignored" };
                var emptyHeaders = Request();
                emptyHeaders.Headers["empty"] = Array.Empty<string>();
                emptyHeaders.Headers["empty-value"] = new[] { "" };
                return new TheoryData<ExperimentalPipelineTheoryData>
                {
                    // Fixed specification vectors also used by the legacy tests, not creator/validator round trips.
                    HashBindingCase("QuerySpecVector", "q", new JArray("b", "a", "c"), "u4LgkGUWhP9MsKrEjA4dizIllDXluDku6ZqCeyuR-JY", querySpec),
                    HashBindingCase("QueryEncodedNameSpace", "q", new JArray("query%20Param1"), Hash("query%20Param1=value1"), queryNameSpace),
                    HashBindingCase("QueryEncodedValueSpace", "q", new JArray("queryParam1"), Hash("queryParam1=val%20ue1"), queryValueSpace),
                    HashBindingCase("QueryNamesAreCaseSensitive", "q", new JArray("a", "b"), Hash("a=one&b=two"), queryCase, false, "IDX23028"),
                    HashBindingCase("EmptyAndMalformedQueryPairsExcluded", "q", new JArray("a", "b"), Hash("a=one&b=two"), ignoredQuery),
                    HashBindingCase("HeaderSpecVectorAndCaseInsensitiveNames", "h", new JArray("content-type", "etag"), "P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs", headerSpec),
                    HashBindingCase("HeaderCrLfHashRejected", "h", new JArray("content-type", "etag"), Hash("content-type: application/json\r\netag: 742-3u8f34-3r2nvv3"), headerSpec, false),
                    HashBindingCase("AuthorizationExcludedFromUnsignedHeaders", "h", new JArray("x-first", "x-second"), Hash("x-first: one\nx-second: two"), authorization),
                    HashBindingCase("AuthorizationCannotBeCoveredByHash", "h", new JArray("authorization"), Hash("authorization: Bearer ignored"), authorization, false, "IDX23027"),
                    HashBindingCase("EmptyHeaderValuesExcluded", "h", new JArray("x-first", "x-second"), Hash("x-first: one\nx-second: two"), emptyHeaders)
                };
            }
        }

        public static TheoryData<ExperimentalPipelineTheoryData> OptionalClaimListTheoryData => new TheoryData<ExperimentalPipelineTheoryData>
        {
            new ExperimentalPipelineTheoryData("NullClaimsToValidateWhenPresent")
            {
                TokenPayload = WithClaim("m", "wrong"),
                Policy = new Policy
                {
                    ValidateTs = false, ValidateM = false, ValidateU = false, ValidateP = false,
                    ValidatePresentClaims = true, ClaimsToValidateWhenPresent = null
                }
            },
            new ExperimentalPipelineTheoryData("UnknownClaimToValidateWhenPresent")
            {
                TokenPayload = WithClaim("m", "wrong"),
                Policy = new Policy
                {
                    ValidateTs = false, ValidateM = false, ValidateU = false, ValidateP = false,
                    ValidatePresentClaims = true, ClaimsToValidateWhenPresent = new[] { "unknown-binding" }
                }
            }
        };

        public class ExperimentalDecryptionKeysTheoryData : ExperimentalPipelineTheoryData
        {
            public ExperimentalDecryptionKeysTheoryData(string testId) : base(testId) { }
            public IList<SecurityKey> ConfiguredKeys { get; set; } = new List<SecurityKey>();
            public IList<SecurityKey> ResolvedKeys { get; set; }
        }

        public static TheoryData<ExperimentalDecryptionKeysTheoryData> DecryptionKeyListTheoryData => new TheoryData<ExperimentalDecryptionKeysTheoryData>
        {
            new ExperimentalDecryptionKeysTheoryData("EmptyResolverResultDoesNotFallBack")
            {
                ConfiguredKeys = new List<SecurityKey> { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key },
                ResolvedKeys = new List<SecurityKey>(),
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23017")
            },
            new ExperimentalDecryptionKeysTheoryData("NullEntryInResolverResult")
            {
                ResolvedKeys = new List<SecurityKey> { null },
                ExpectedFailure = ValidationFailureType.NullArgument,
                ExpectedException = ExpectedException.ArgumentNullException()
            },
            new ExperimentalDecryptionKeysTheoryData("WrongResolverKeyDoesNotFallBack")
            {
                ConfiguredKeys = new List<SecurityKey> { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key },
                ResolvedKeys = new List<SecurityKey> { new SymmetricSecurityKey(new byte[32]) },
                ExpectedFailure = SignedHttpRequestValidationFailure.PopKey,
                ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), innerTypeExpected: typeof(SecurityTokenDecryptionFailedException))
            },
            new ExperimentalDecryptionKeysTheoryData("CorrectResolverKeyOverridesWrongConfiguredKey")
            {
                ConfiguredKeys = new List<SecurityKey> { new SymmetricSecurityKey(new byte[32]) },
                ResolvedKeys = new List<SecurityKey> { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }
            },
            new ExperimentalDecryptionKeysTheoryData("ConfiguredKeysTrySecondKey")
            {
                ConfiguredKeys = new List<SecurityKey>
                {
                    new SymmetricSecurityKey(new byte[32]), SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key
                }
            }
        };
    }
}
