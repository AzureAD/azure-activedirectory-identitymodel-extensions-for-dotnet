// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;
using static Microsoft.IdentityModel.TestUtils.ReplayIdentityTestUtilities;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class ReplayCacheIdentityTests
    {
        public static IEnumerable<object[]> VariantCases()
        {
            foreach (bool saml2 in new[] { false, true })
                foreach (bool experimental in new[] { false, true })
                    foreach (bool reverse in new[] { false, true })
                        yield return new object[] { saml2, experimental, reverse };
        }

        [Theory]
        [MemberData(nameof(VariantCases))]
        public async Task SamlReplayIdentityRejectsSignatureVariants(bool saml2, bool experimental, bool reverse)
        {
            // Arrange
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa) { KeyId = "synthetic-replay-key" };
            SecurityTokenHandler handler = Handler(saml2);
            string token = CreateToken(handler, key, "https://issuer.example", "_same-id");
            string twin = ChangeSignature(token, true);
            Assert.NotEqual(token, twin);
            var cache = new StatefulReplayCache();
            var current = Current(key, cache);
            var parameters = Experimental(key, cache);
            current.IssuerValidator = (issuer, securityToken, vp) => "https://common-issuer-alias";
            parameters.IssuerValidatorAsync = new AliasIssuerValidator(parameters.IssuerValidatorAsync);

            // Act / Assert: both signatures must pass independently, in either arrival order.
            Assert.Null(await Validate(handler, token, experimental, Current(key, new StatefulReplayCache()), Experimental(key, new StatefulReplayCache())));
            Assert.Null(await Validate(handler, twin, experimental, Current(key, new StatefulReplayCache()), Experimental(key, new StatefulReplayCache())));
            Assert.Null(await Validate(handler, reverse ? twin : token, experimental, current, parameters));
            Assert.IsType<SecurityTokenReplayDetectedException>(
                await Validate(handler, reverse ? token : twin, experimental, current, parameters));
            string identity = Assert.Single(cache.Adds);
            Assert.StartsWith("IM.Replay.v1.", identity);
            Assert.Equal(new[] { identity, identity }, cache.Finds);
            Assert.Equal(handler.ReadToken(token).ValidTo, Assert.Single(cache.Expirations));

            // The scope is the authenticated assertion issuer, NOT a custom issuer-validator alias.
            Assert.Null(await Validate(handler, CreateToken(handler, key, "https://Issuer.example", "_same-id"),
                experimental, current, parameters));
            Assert.Null(await Validate(handler, CreateToken(handler, key, "https://issuer.example", "_other-id"),
                experimental, current, parameters));
            Assert.Equal(3, cache.Adds.Count);
            Assert.Equal(3, new HashSet<string>(cache.Adds, StringComparer.Ordinal).Count);

            // Current and experimental entry points share the same identity namespace.
            var otherCache = new StatefulReplayCache();
            Assert.Null(await Validate(handler, token, !experimental, Current(key, otherCache), Experimental(key, otherCache)));
            Assert.Equal(identity, Assert.Single(otherCache.Adds));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task SamlReplayIdentityRequiresExpirationForCache(bool saml2)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            SecurityTokenHandler handler = Handler(saml2);
            string token = CreateToken(handler, key, "https://issuer.example", "_no-conditions", true);
            var cache = new StatefulReplayCache();
            var parameters = Current(key, cache);
            // Removing Conditions also removes its audience restriction.
            parameters.RequireAudience = false;
            parameters.ValidateAudience = false;
            parameters.ValidateLifetime = false;
            parameters.UseTokenReplayCacheIdentity = false;
            Assert.Null(await Validate(handler, token, false, parameters, Experimental(key, cache)));
            Assert.Empty(cache.Adds);
            parameters.UseTokenReplayCacheIdentity = true;
            Assert.IsType<SecurityTokenNoExpirationException>(
                await Validate(handler, token, false, parameters, Experimental(key, cache)));
            Assert.Empty(cache.Finds);
            Assert.Empty(cache.Adds);
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task SamlReplayIdentityDoesNotCacheFailedValidation(bool saml2, bool experimental)
        {
            // Arrange
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            SecurityTokenHandler handler = Handler(saml2);
            string token = CreateToken(handler, key, "https://issuer.example", "_same-id");
            var cache = new StatefulReplayCache();
            var current = Current(key, cache);
            var parameters = Experimental(key, cache);

            // Act / Assert: invalid signature and valid signature rejected by key policy do not reserve ID.
            Assert.NotNull(await Validate(handler, ChangeSignature(token, false), experimental, current, parameters));
            Assert.Empty(cache.Finds);
            Assert.Empty(cache.Adds);
            current.IssuerSigningKeyValidator = (signingKey, securityToken, vp) => false;
            var original = parameters.SignatureKeyValidator;
            parameters.SignatureKeyValidator = new RejectSigningKey();
            Assert.IsType<SecurityTokenInvalidSigningKeyException>(await Validate(handler, token, experimental, current, parameters));
            Assert.Empty(cache.Finds);
            Assert.Empty(cache.Adds);
            current.IssuerSigningKeyValidator = null;
            parameters.SignatureKeyValidator = original;
            Assert.Null(await Validate(handler, token, experimental, current, parameters));
            Assert.Single(cache.Adds);
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task SamlReplayIdentityCompatibility(bool saml2, bool experimental)
        {
            // Arrange
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            SecurityTokenHandler handler = Handler(saml2);
            string token = CreateToken(handler, key, "https://issuer.example", "_same-id");
            string twin = ChangeSignature(token, true);
            var cache = new StatefulReplayCache();
            var current = Current(key, cache);
            var parameters = Experimental(key, cache);
            current.UseTokenReplayCacheIdentity = false;
            parameters.UseTokenReplayCacheIdentity = false;
            string[] originals = { Canonical(handler, token), Canonical(handler, twin) };

            // Act / Assert: legacy strings include signature and deliberately remain distinct.
            Assert.Null(await Validate(handler, token, experimental, current, parameters));
            Assert.Null(await Validate(handler, twin, experimental, current, parameters));
            Assert.Equal(originals, cache.Adds);
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(handler, token, experimental, current, parameters));

            cache = new StatefulReplayCache { FailAdds = true };
            current = Current(key, cache);
            parameters = Experimental(key, cache);
            var received = new List<string>();
            current.TokenReplayValidator = (expiration, original, vp) =>
            {
                received.Add(original);
                return true;
            };
            var custom = new RecordingReplayValidator();
            parameters.TokenReplayValidator = custom;
            Assert.Null(await Validate(handler, token, experimental, current, parameters));
            Assert.Null(await Validate(handler, twin, experimental, current, parameters));
            Assert.Equal(originals, experimental ? custom.Tokens : received);
            Assert.Empty(cache.Finds);
            Assert.Empty(cache.Adds);
            current.TokenReplayValidator = (expiration, original, vp) => false;
            custom.Accept = false;
            Assert.IsType<SecurityTokenReplayDetectedException>(await Validate(handler, token, experimental, current, parameters));
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task SamlReplayIdentityFailsClosedOnCacheAddFailure(bool saml2, bool experimental)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            SecurityTokenHandler handler = Handler(saml2);
            var cache = new StatefulReplayCache { FailAdds = true };
            Exception error = await Validate(handler,
                CreateToken(handler, key, "https://issuer.example", "_same-id"), experimental,
                Current(key, cache), Experimental(key, cache));
            if (experimental)
                Assert.IsType<SecurityTokenReplayDetectedException>(error);
            else
                Assert.IsType<SecurityTokenReplayAddFailedException>(error);
            Assert.Contains("IDX10229", error.Message);
            Assert.Equal(Assert.Single(cache.Finds), Assert.Single(cache.Adds));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void SamlReplayIdentityProtectedOverrideReceivesOriginalToken(bool saml2)
        {
            using ECDsa ecdsa = CreateEcdsa(256);
            var key = new ECDsaSecurityKey(ecdsa);
            var received = new List<string>();
            SecurityTokenHandler handler = saml2 ? new ReplayOverrideSaml2(received) : new ReplayOverrideSaml(received);
            string token = CreateToken(handler, key, "https://issuer.example", "_same-id");
            string twin = ChangeSignature(token, true);
            var cache = new StatefulReplayCache { FailAdds = true };
            var parameters = Current(key, cache);
            handler.ValidateToken(token, parameters, out _);
            handler.ValidateToken(twin, parameters, out _);
            Assert.Equal(new[] { Canonical(handler, token), Canonical(handler, twin) }, received);
            Assert.Empty(cache.Adds);
        }

        private sealed class ReplayOverrideSaml : SamlSecurityTokenHandler
        {
            private readonly List<string> _received;
            internal ReplayOverrideSaml(List<string> received) { _received = received; }
            protected override void ValidateTokenReplay(DateTime? expiration, string token, TokenValidationParameters validationParameters)
            {
                _received.Add(token);
            }

        }

        private sealed class AliasIssuerValidator : IIssuerValidator
        {
            private readonly IIssuerValidator _original;
            internal AliasIssuerValidator(IIssuerValidator original) { _original = original; }
            public async Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer, SecurityToken securityToken, ValidationParameters validationParameters,
                CallContext callContext, CancellationToken cancellationToken)
            {
                var result = await _original.ValidateIssuerAsync(
                    issuer, securityToken, validationParameters, callContext, cancellationToken);
                if (!result.Succeeded)
                    return result;
                return new ValidatedIssuer("https://common-issuer-alias", result.Result.ValidationSource);
            }
        }

        private sealed class ReplayOverrideSaml2 : Saml2SecurityTokenHandler
        {
            private readonly List<string> _received;
            internal ReplayOverrideSaml2(List<string> received) { _received = received; }
            protected override void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
            {
                _received.Add(securityToken);
            }
        }

        private static SecurityTokenHandler Handler(bool saml2) => saml2 ? new Saml2SecurityTokenHandler() : new SamlSecurityTokenHandler();

        private static string Canonical(SecurityTokenHandler handler, string token)
        {
            SecurityToken parsed = handler.ReadToken(token);
            return parsed is SamlSecurityToken saml ? saml.Assertion.CanonicalString : ((Saml2SecurityToken)parsed).Assertion.CanonicalString;
        }

        private static string CreateToken(SecurityTokenHandler handler, SecurityKey key, string issuer, string id, bool omitConditions = false)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer, Audience = "https://audience.example",
                Subject = new CaseSensitiveClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "replay-subject"),
                    new Claim(ClaimTypes.Role, "reader")
                }),
                NotBefore = DateTime.UtcNow.AddMinutes(-1), Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.Sha256Digest)
            };
            SecurityToken token = handler.CreateToken(descriptor);
            if (token is SamlSecurityToken saml)
            {
                saml.Assertion.AssertionId = id;
                if (omitConditions)
                    saml.Assertion.Conditions = null;
            }
            else
            {
                ((Saml2SecurityToken)token).Assertion.Id = new Saml2Id(id);
                if (omitConditions)
                    ((Saml2SecurityToken)token).Assertion.Conditions = null;
            }

            return handler.WriteToken(token);
        }

        private static string ChangeSignature(string token, bool twin)
        {
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            document.LoadXml(token);
            XmlNode signature = document.GetElementsByTagName("SignatureValue", "http://www.w3.org/2000/09/xmldsig#")[0];
            signature.InnerText = Convert.ToBase64String(twin ? TwinSignature(Convert.FromBase64String(signature.InnerText)) : new byte[64]);
            return document.OuterXml;
        }

        private static TokenValidationParameters Current(SecurityKey key, StatefulReplayCache cache) => new TokenValidationParameters
        {
            IssuerSigningKey = key, ValidIssuers = new[] { "https://issuer.example", "https://Issuer.example" },
            ValidAudience = "https://audience.example", ValidateTokenReplay = true,
            TokenReplayCache = cache, UseTokenReplayCacheIdentity = true
        };

        private static ValidationParameters Experimental(SecurityKey key, StatefulReplayCache cache)
        {
            var parameters = new ValidationParameters { TokenReplayCache = cache, UseTokenReplayCacheIdentity = true };
            parameters.SigningKeys.Add(key);
            parameters.ValidIssuers.Add("https://issuer.example");
            parameters.ValidIssuers.Add("https://Issuer.example");
            parameters.ValidAudiences.Add("https://audience.example");
            return parameters;
        }

        private static async Task<Exception> Validate(SecurityTokenHandler handler, string token, bool experimental,
            TokenValidationParameters current, ValidationParameters parameters)
        {
            if (experimental)
            {
                var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(token, parameters, new CallContext());
                return result.Succeeded ? null : result.Error.GetException();
            }

            TokenValidationResult validation = await handler.ValidateTokenAsync(token, current);
            Assert.Equal(validation.Exception == null, validation.IsValid);
            return validation.Exception;
        }
    }
}
