// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
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

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public partial class ExperimentalSignedHttpRequestPipelineTests
    {
        public class ExperimentalRoundtripTheoryData : ExperimentalPipelineTheoryData
        {
            public ExperimentalRoundtripTheoryData(string testId) : base(testId) { }
            public string AccessToken { get; set; }
            public string CnfClaimValue { get; set; }
            public SignedHttpRequestCreationParameters CreationParameters { get; set; } = AllCreationClaims();
        }

        private static SignedHttpRequestCreationParameters AllCreationClaims() => new SignedHttpRequestCreationParameters
        {
            // Freeze ts through AdditionalPayloadClaims: the legacy creator has no TimeProvider seam.
            CreateTs = false,
            CreateQ = true,
            CreateH = true,
            CreateB = true
        };

        [Theory, MemberData(nameof(ExperimentalRoundtripTheoryDataSet), DisableDiscoveryEnumeration = true)]
        public async Task RoundtripsCreatedSignedHttpRequest(ExperimentalRoundtripTheoryData theoryData)
        {
            // Arrange: same descriptor/handler/fixture flow as SignedHttpRequestE2ETests.Roundtrips.
            var handler = new SignedHttpRequestHandler();
            var request = Request();
            var descriptor = new SignedHttpRequestDescriptor(theoryData.AccessToken, request,
                theoryData.SigningCredentials, theoryData.CreationParameters)
            {
                CnfClaimValue = theoryData.CnfClaimValue,
                CustomNonceValue = "roundtrip-nonce",
                AdditionalPayloadClaims = new Dictionary<string, object> { ["ts"] = EpochTime.GetIntDate(Now.UtcDateTime) }
            };
            string signedHttpRequest = handler.CreateSignedHttpRequest(descriptor);
            var parameters = Parameters();
            var context = new Context(signedHttpRequest, request, new TokenValidationParameters(), theoryData.Policy ?? AllClaims(), theoryData.CallContext);

            // Act
            var result = await handler.ValidateSignedHttpRequestAsync(context, parameters, CancellationToken.None);

            // Assert
            AssertPipelineOutcome(result, theoryData);
            if (result.Succeeded)
            {
                var token = result.Result.ValidatedToken;
                Assert.Equal(signedHttpRequest, result.Result.SignedHttpRequest);
                Assert.Equal(theoryData.AccessToken, token.GetPayloadValue<string>("at"));
                Assert.Equal("GET", token.GetPayloadValue<string>("m"));
                Assert.Equal("www.contoso.com", token.GetPayloadValue<string>("u"));
                Assert.Equal("/path1", token.GetPayloadValue<string>("p"));
                Assert.Equal("roundtrip-nonce", token.GetPayloadValue<string>("nonce"));
                Assert.Equal(EpochTime.GetIntDate(Now.UtcDateTime), token.GetPayloadValue<long>("ts"));
                Assert.Equal(Hash("a=one&b=two"), token.GetPayloadValue<System.Text.Json.JsonElement>("q")[1].GetString());
                Assert.Equal(Hash("x-first: one\nx-second: two"), token.GetPayloadValue<System.Text.Json.JsonElement>("h")[1].GetString());
                Assert.Equal(Hash("body"), token.GetPayloadValue<string>("b"));
                // An x5c-only JWK has no n/e members; its converted certificate supplies the RSA thumbprint.
                SecurityKey resolved = token.SigningKey is JsonWebKey jwk && jwk.ConvertedSecurityKey is X509SecurityKey
                    ? jwk.ConvertedSecurityKey : token.SigningKey;
                Assert.Equal(theoryData.SigningCredentials.Key.ComputeJwkThumbprint(), resolved.ComputeJwkThumbprint());
                Assert.Equal("Bob@contoso.com", result.Result.AccessTokenValidationResult.ClaimsIdentity.FindFirst("email").Value);
                Assert.Same(parameters, result.Result.AccessTokenValidationResult.ValidationParameters);
            }
        }

        public static TheoryData<ExperimentalRoundtripTheoryData> ExperimentalRoundtripTheoryDataSet
        {
            get
            {
#if NET472_OR_GREATER || NET
                var ecCredentials = new SigningCredentials(KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdsaSha256);
#endif
                var x509 = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var x5cCnf = new JObject
                {
                    ["jwk"] = new JObject
                    {
                        ["kty"] = "RSA",
                        ["kid"] = x509.KeyId,
                        ["x5c"] = new JArray(Convert.ToBase64String(x509.Certificate.RawData))
                    }
                };
                var symmetric = SymmetricCredentials();
                var symmetricJwk = SignedHttpRequestTestUtils.DefaultJwe;
                symmetricJwk["k"] = Base64UrlEncoder.Encode(((SymmetricSecurityKey)symmetric.Key).Key);
                var symmetricCnf = new JObject { ["jwe"] = SignedHttpRequestTestUtils.EncryptToken(symmetricJwk.ToString(Formatting.None)) };
                return new TheoryData<ExperimentalRoundtripTheoryData>
                {
                    new ExperimentalRoundtripTheoryData("ValidJwkRsa")
                    {
                        First = true, AccessToken = AccessToken(), SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials
                    },
                    new ExperimentalRoundtripTheoryData("ValidEncryptedAt")
                    {
                        AccessToken = AccessToken(encrypt: true), SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials
                    },
#if NET472_OR_GREATER || NET
                    new ExperimentalRoundtripTheoryData("ValidJwkEcdsa")
                    {
                        AccessToken = AccessToken(SignedHttpRequestTestUtils.DefaultCnfJwkEcdsa), SigningCredentials = ecCredentials
                    },
                    new ExperimentalRoundtripTheoryData("ValidEcdsaThumbprint")
                    {
                        AccessToken = AccessToken(SignedHttpRequestTestUtils.DefaultCnfJwkEcdsaThumbprint), SigningCredentials = ecCredentials
                    },
#endif
                    new ExperimentalRoundtripTheoryData("ValidX5cThumbprint")
                    {
                        AccessToken = AccessToken(new JObject { ["kid"] = Base64UrlEncoder.Encode(x509.ComputeJwkThumbprint()) }),
                        SigningCredentials = new SigningCredentials(x509, SecurityAlgorithms.RsaSha256),
                        CnfClaimValue = x5cCnf.ToString(Formatting.None)
                    },
                    new ExperimentalRoundtripTheoryData("ValidJweSymmetricKeyThumbprint")
                    {
                        AccessToken = AccessToken(new JObject { ["kid"] = Base64UrlEncoder.Encode(symmetric.Key.ComputeJwkThumbprint()) }),
                        SigningCredentials = symmetric,
                        CnfClaimValue = symmetricCnf.ToString(Formatting.None),
                        Policy = DecryptionPolicy(SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key)
                    },
                    new ExperimentalRoundtripTheoryData("ValidCnfAsString")
                    {
                        AccessToken = AccessToken(new JValue(SignedHttpRequestTestUtils.DefaultCnfJwk.ToString(Formatting.None))),
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials
                    },
                    new ExperimentalRoundtripTheoryData("InvalidBadPopSigningKey")
                    {
                        AccessToken = AccessToken(), SigningCredentials = new SigningCredentials(KeyingMaterial.RsaSecurityKey_4096, SecurityAlgorithms.RsaSha256),
                        ExpectedFailure = SignedHttpRequestValidationFailure.Signature,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException))
                    },
                    new ExperimentalRoundtripTheoryData("InvalidNoUClaim")
                    {
                        AccessToken = AccessToken(), SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        CreationParameters = new SignedHttpRequestCreationParameters { CreateTs = false, CreateU = false, CreateQ = true, CreateH = true, CreateB = true },
                        ExpectedFailure = SignedHttpRequestValidationFailure.Claim, ExpectedClaim = "u",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23042")
                    }
                };
            }
        }

        private static List<string> NonceList = ["nonce1", "nonce2", "nonce1"];

        [Fact]
        public async Task SignedHttpRequestReplayValidationRejectsPreviouslyAcceptedNonce()
        {
            // Arrange: legacy nonce1 / nonce2 / nonce1 replay sequence, with the experimental result contract.
            var cache = new HashSet<string>(StringComparer.Ordinal);
            var observed = new List<string>();
            var replay = new Mock<IReplayValidator>(MockBehavior.Strict);
            replay.Setup(x => x.ValidateReplayAsync(It.IsAny<SecurityToken>(), It.IsAny<Context>(), CancellationToken.None))
                .Returns((SecurityToken token, Context context, CancellationToken cancellation) =>
                {
                    string nonce = ((JsonWebToken)token).GetPayloadValue<string>("nonce");
                    observed.Add(nonce);
                    return Task.FromResult(new ValidationResult<bool, ValidationError>(cache.Add(nonce)));
                });
            var policy = AllClaims();
            policy.ReplayValidator = replay.Object;
            var handler = new SignedHttpRequestHandler();
            Context CreateRequest(string nonce)
            {
                var request = Request();
                var descriptor = new SignedHttpRequestDescriptor(AccessToken(), request,
                    SignedHttpRequestTestUtils.DefaultSigningCredentials, AllCreationClaims())
                {
                    CustomNonceValue = nonce,
                    AdditionalPayloadClaims = new Dictionary<string, object> { ["ts"] = EpochTime.GetIntDate(Now.UtcDateTime) }
                };
                return new Context(handler.CreateSignedHttpRequest(descriptor), request, new TokenValidationParameters(), policy);
            }

            // Act
            var first = await Validate(CreateRequest("nonce1"));
            var second = await Validate(CreateRequest("nonce2"));
            var duplicate = await Validate(CreateRequest("nonce1"));

            // Assert
            Assert.True(first.Succeeded, first.Error?.Message);
            Assert.True(second.Succeeded, second.Error?.Message);
            Assert.Equal("nonce1", first.Result.ValidatedToken.GetPayloadValue<string>("nonce"));
            Assert.Equal("nonce2", second.Result.ValidatedToken.GetPayloadValue<string>("nonce"));
            Assert.IsType<SignedHttpRequestValidationException>(Error(duplicate, SignedHttpRequestValidationFailure.Replay).GetException());
            Assert.Equal(NonceList, observed);
            Assert.Equal(2, cache.Count);
            Assert.Contains("nonce1", cache);
            Assert.Contains("nonce2", cache);
            replay.Verify(x => x.ValidateReplayAsync(It.IsAny<SecurityToken>(), It.IsAny<Context>(), CancellationToken.None), Times.Exactly(3));
            replay.VerifyNoOtherCalls();
        }
    }
}
