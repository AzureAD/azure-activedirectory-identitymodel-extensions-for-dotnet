// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;
using static Microsoft.IdentityModel.TestUtils.ReplayIdentityTestUtilities;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class ReplayCacheIdentityTests
    {
        // Mode 0: JwtSecurityTokenHandler; 1: JsonWebTokenHandler; 2: experimental JSON.
        public static IEnumerable<object[]> TwinCases()
        {
            foreach (int mode in new[] { 0, 1, 2 })
                foreach (int bits in new[] { 256, 384, 521 })
                    foreach (bool reverse in new[] { false, true })
                        yield return new object[] { mode, bits, reverse };
        }

        [Theory]
        [MemberData(nameof(TwinCases))]
        public async Task JwtReplayIdentityRejectsSignatureTwins(int mode, int bits, bool reverse)
        {
            // Arrange: generated test-only keys; neither signature is privileged as "canonical".
            using ECDsa ecdsa = CreateEcdsa(bits);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, bits);
            string twin = Twin(token);
            Assert.NotEqual(token, twin);
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            var experimental = Experimental(key, cache);
            string first = reverse ? twin : token;
            string second = reverse ? token : twin;

            // Act / Assert: prove both signatures valid independently before testing replay.
            Assert.Null(await Validate(mode, token, Current(key, new StatefulReplayCache()), Experimental(key, new StatefulReplayCache())));
            Assert.Null(await Validate(mode, twin, Current(key, new StatefulReplayCache()), Experimental(key, new StatefulReplayCache())));
            Assert.Null(await Validate(mode, first, parameters, experimental));
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(mode, second, parameters, experimental));
            string identity = Assert.Single(cache.Adds);
            Assert.StartsWith("IM.Replay.v1.", identity);
            Assert.Equal(56, identity.Length);
            Assert.Equal(new[] { identity, identity }, cache.Finds);
            Assert.Equal(new JsonWebToken(token).ValidTo, Assert.Single(cache.Expirations));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task JwtReplayIdentityDoesNotCacheFailedValidation(int mode)
        {
            // Arrange
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, 256);
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            parameters.ValidateSignatureLast = true;
            var experimental = Experimental(key, cache);
            int lastDot = token.LastIndexOf('.');
            string corrupt = token.Remove(lastDot + 1) + Base64UrlEncoder.Encode(new byte[64]);

            // Act / Assert: signature-last must not reserve the genuine signing input.
            Assert.NotNull(await Validate(mode, corrupt, parameters, experimental));
            Assert.Empty(cache.Finds);
            Assert.Empty(cache.Adds);
            parameters.IssuerSigningKeyValidator = (signingKey, securityToken, validationParameters) => false;
            var originalKeyValidator = experimental.SignatureKeyValidator;
            experimental.SignatureKeyValidator = new RejectSigningKey();
            Assert.IsType<SecurityTokenInvalidSigningKeyException>(await Validate(mode, token, parameters, experimental));
            Assert.Empty(cache.Adds);
            if (mode != 2)
            {
                parameters.SignatureValidator = (original, vp) => mode == 0
                    ? new JwtSecurityToken(original) { SigningKey = key }
                    : new JsonWebToken(original) { SigningKey = key };
                Assert.IsType<SecurityTokenInvalidSigningKeyException>(await Validate(mode, token, parameters, experimental));
                Assert.Empty(cache.Adds);
                parameters.SignatureValidator = null;
            }
            parameters.IssuerSigningKeyValidator = null;
            experimental.SignatureKeyValidator = originalKeyValidator;
            parameters.ValidTypes = new[] { "not-JWT" };
            experimental.ValidTypes.Add("not-JWT");
            Assert.IsType<SecurityTokenInvalidTypeException>(await Validate(mode, token, parameters, experimental));
            Assert.Empty(cache.Adds);
            parameters.ValidTypes = null;
            experimental.ValidTypes.Clear();
            Assert.Null(await Validate(mode, token, parameters, experimental));
            Assert.Single(cache.Adds);
        }

        [Theory]
        [InlineData(0, false)]
        [InlineData(0, true)]
        [InlineData(1, false)]
        [InlineData(1, true)]
        [InlineData(2, false)]
        [InlineData(2, true)]
        public async Task JwtReplayIdentityPreservesReplayCallbackOrdering(int mode, bool identityMode)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, 256);
            var events = new List<string>();
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            parameters.UseTokenReplayCacheIdentity = identityMode;
            parameters.ValidateSignatureLast = true;
            parameters.TokenReplayValidator = (expiration, original, vp) =>
            {
                events.Add("replay");
                return true;
            };
            parameters.IssuerSigningKeyValidator = (signingKey, securityToken, vp) =>
            {
                events.Add("key");
                return true;
            };
            var experimental = Experimental(key, cache);
            experimental.UseTokenReplayCacheIdentity = identityMode;
            var custom = new RecordingReplayValidator { OnValidation = () => events.Add("replay") };
            experimental.TokenReplayValidator = custom;
            experimental.SignatureKeyValidator = new RecordingKeyPolicy(experimental.SignatureKeyValidator, events);
            string corrupt = token.Remove(token.LastIndexOf('.') + 1) + Base64UrlEncoder.Encode(new byte[64]);
            Assert.NotNull(await Validate(mode, corrupt, parameters, experimental));
            Assert.Equal(identityMode ? 0 : 1, mode == 2 ? custom.Tokens.Count : events.Count);
            events.Clear();
            custom.Tokens.Clear();
            Assert.Null(await Validate(mode, token, parameters, experimental));
            if (mode == 2)
                Assert.Equal(new[] { token }, custom.Tokens);
            Assert.Equal(identityMode ? new[] { "key", "replay" } : new[] { "replay", "key" }, events);
            Assert.Empty(cache.Adds);
        }

        [Theory]
        [InlineData(0, false)]
        [InlineData(0, true)]
        [InlineData(1, false)]
        [InlineData(1, true)]
        [InlineData(2, false)]
        [InlineData(2, true)]
        public async Task JwtReplayIdentitySurvivesConfigurationRetry(int mode, bool useLkg)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            using ECDsa staleEcdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa) { KeyId = "current-key" };
            var staleKey = new ECDsaSecurityKey(staleEcdsa) { KeyId = "stale-key" };
            string token = CreateToken(key, 256);
            var stale = new ReplayConfiguration { Issuer = "https://issuer.example" };
            stale.SigningKeys.Add(staleKey);
            var good = new ReplayConfiguration { Issuer = "https://issuer.example" };
            good.SigningKeys.Add(key);
            var manager = useLkg ? new MockConfigurationManager<ReplayConfiguration>(stale, good)
                : new MockConfigurationManager<ReplayConfiguration>(stale) { RefreshedConfiguration = good };
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            parameters.IssuerSigningKey = null;
            parameters.ValidateSignatureLast = true;
            parameters.ConfigurationManager = manager;
            var experimental = Experimental(key, cache);
            experimental.SigningKeys.Clear();
            experimental.ConfigurationManager = manager;

            Assert.Null(await Validate(mode, token, parameters, experimental));
            string identity = Assert.Single(cache.Adds);
            Assert.Equal(identity, Assert.Single(cache.Finds));
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(mode, Twin(token), parameters, experimental));
            Assert.Single(cache.Adds);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task JwtReplayIdentityPreservesExactSigningInput(int mode)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, 256);
            string[] parts = token.Split('.');
            string headerWhitespace = Base64UrlEncoder.Encode(" " + Base64UrlEncoder.Decode(parts[0]));
            string payloadWhitespace = Base64UrlEncoder.Encode(" " + Base64UrlEncoder.Decode(parts[1]));
            string[] inputs = { parts[0] + "." + parts[1], headerWhitespace + "." + parts[1], parts[0] + "." + payloadWhitespace };
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            var experimental = Experimental(key, cache);
            foreach (string input in inputs)
            {
                string signed = input + "." + Base64UrlEncoder.Encode(ecdsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256));
                Assert.Null(await Validate(mode, signed, parameters, experimental));
            }

            Assert.Equal(3, cache.Adds.Count);
            Assert.Equal(3, new HashSet<string>(cache.Adds, StringComparer.Ordinal).Count);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task JwtReplayIdentityCompatibility(int mode)
        {
            // Arrange
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, 256);
            string twin = Twin(token);
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            var experimental = Experimental(key, cache);
            parameters.UseTokenReplayCacheIdentity = false;
            experimental.UseTokenReplayCacheIdentity = false;

            // Act / Assert: default mode intentionally retains the old vulnerable input contract.
            Assert.Null(await Validate(mode, token, parameters, experimental));
            Assert.Null(await Validate(mode, twin, parameters, experimental));
            Assert.Equal(new[] { token, twin }, cache.Adds);
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(mode, token, parameters, experimental));

            var callbackCache = new StatefulReplayCache { FailAdds = true };
            parameters = Current(key, callbackCache);
            experimental = Experimental(key, callbackCache);
            var received = new List<string>();
            parameters.TokenReplayValidator = (expiration, original, vp) =>
            {
                Assert.Same(parameters, vp);
                received.Add(original);
                return true;
            };
            var custom = new RecordingReplayValidator();
            experimental.TokenReplayValidator = custom;
            Assert.Null(await Validate(mode, token, parameters, experimental));
            Assert.Null(await Validate(mode, twin, parameters, experimental));
            Assert.Equal(new[] { token, twin }, mode == 2 ? custom.Tokens : received);
            Assert.Empty(callbackCache.Finds);
            Assert.Empty(callbackCache.Adds);
            parameters.TokenReplayValidator = (expiration, original, vp) => false;
            custom.Accept = false;
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(mode, token, parameters, experimental));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task JwtReplayIdentityUsesInnerJws(int mode)
        {
            // Arrange: separately encrypt the same JWS with randomized IVs.
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string inner = CreateToken(key, 256);
            var encryptionKey = new SymmetricSecurityKey(new byte[16]);
            var credentials = new EncryptingCredentials(encryptionKey, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);
            var handler = new JsonWebTokenHandler();
            string first = handler.EncryptToken(inner, credentials);
            string second = handler.EncryptToken(Twin(inner), credentials);
            Assert.NotEqual(first, second);
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            parameters.TokenDecryptionKey = encryptionKey;
            var experimental = Experimental(key, cache);
            experimental.DecryptionKeys.Add(encryptionKey);

            // Act / Assert
            Assert.Null(await Validate(mode, first, parameters, experimental));
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(mode, second, parameters, experimental));
            var cleartextCache = new StatefulReplayCache();
            Assert.Null(await Validate(mode, inner, Current(key, cleartextCache), Experimental(key, cleartextCache)));
            Assert.Equal(Assert.Single(cleartextCache.Adds), Assert.Single(cache.Adds));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task JwtReplayIdentityFailsClosedOnCacheAddFailure(int mode)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            var cache = new StatefulReplayCache { FailAdds = true };
            Exception error = await Validate(mode, CreateToken(key, 256), Current(key, cache), Experimental(key, cache));
            if (mode == 2)
                Assert.IsType<SecurityTokenReplayDetectedException>(error);
            else
                Assert.IsType<SecurityTokenReplayAddFailedException>(error);
            Assert.Contains("IDX10229", error.Message);
            Assert.Equal(Assert.Single(cache.Finds), Assert.Single(cache.Adds));
        }

        [Fact]
        public void JwtReplayIdentityProtectedOverrideReceivesOriginalToken()
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            string token = CreateToken(key, 256);
            var cache = new StatefulReplayCache { FailAdds = true };
            var parameters = Current(key, cache);
            var handler = new ReplayOverrideHandler();
            handler.ValidateToken(token, parameters, out _);
            handler.ValidateToken(Twin(token), parameters, out _);
            Assert.Equal(new[] { token, Twin(token) }, handler.Tokens);
            Assert.Same(parameters, handler.Parameters);
            Assert.Empty(cache.Adds);
        }

        private sealed class ReplayOverrideHandler : JwtSecurityTokenHandler
        {
            internal List<string> Tokens { get; } = new List<string>();
            internal TokenValidationParameters Parameters { get; private set; }
            protected override void ValidateTokenReplay(DateTime? expires, string securityToken, TokenValidationParameters validationParameters)
            {
                Tokens.Add(securityToken);
                Parameters = validationParameters;
            }
        }

        private sealed class ReplayConfiguration : BaseConfiguration { }

        private sealed class RecordingKeyPolicy : ISignatureKeyValidator
        {
            private readonly ISignatureKeyValidator _original;
            private readonly List<string> _events;
            internal RecordingKeyPolicy(ISignatureKeyValidator original, List<string> events)
            {
                _original = original;
                _events = events;
            }
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey, SecurityToken securityToken, ValidationParameters validationParameters, CallContext callContext)
            {
                _events.Add("key");
                return _original.ValidateSignatureKey(signingKey, securityToken, validationParameters, callContext);
            }
        }

        private static string CreateToken(SecurityKey key, int bits)
        {
            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://issuer.example", Audience = "replay-tests",
                NotBefore = DateTime.UtcNow.AddMinutes(-1), Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(key, bits == 256 ? SecurityAlgorithms.EcdsaSha256 :
                    bits == 384 ? SecurityAlgorithms.EcdsaSha384 : SecurityAlgorithms.EcdsaSha512)
            });
        }

        private static string Twin(string token)
        {
            int dot = token.LastIndexOf('.');
            return token.Remove(dot + 1) + Base64UrlEncoder.Encode(TwinSignature(Base64UrlEncoder.DecodeBytes(token.Substring(dot + 1))));
        }

        private static TokenValidationParameters Current(SecurityKey key, StatefulReplayCache cache) => new TokenValidationParameters
        {
            IssuerSigningKey = key, ValidIssuer = "https://issuer.example", ValidAudience = "replay-tests",
            ValidateTokenReplay = true, TokenReplayCache = cache, UseTokenReplayCacheIdentity = true
        };

        private static ValidationParameters Experimental(SecurityKey key, StatefulReplayCache cache)
        {
            var parameters = new ValidationParameters { UseTokenReplayCacheIdentity = true, TokenReplayCache = cache };
            parameters.SigningKeys.Add(key);
            parameters.ValidIssuers.Add("https://issuer.example");
            parameters.ValidAudiences.Add("replay-tests");
            return parameters;
        }

        private static async Task<Exception> Validate(int mode, string token, TokenValidationParameters parameters, ValidationParameters experimental)
        {
            if (mode == 2)
            {
                var result = await ((IResultBasedValidation)new JsonWebTokenHandler()).ValidateTokenAsync(token, experimental, new CallContext());
                return result.Succeeded ? null : result.Error.GetException();
            }

            TokenValidationResult current = mode == 0
                ? await new JwtSecurityTokenHandler().ValidateTokenAsync(token, parameters)
                : await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters);
            Assert.Equal(current.Exception == null, current.IsValid);
            return current.Exception;
        }
    }
}
