//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Test some key extensibility scenarios
    /// </summary>
    public class ExtensibilityTests
    {
        [Fact(DisplayName = "ExtensibilityTests: JwtSecurityTokenHandler")]
        public void JwtSecurityTokenHandler_Extensibility()
        {
            DerivedJwtSecurityTokenHandler handler = new DerivedJwtSecurityTokenHandler()
            {
                DerivedTokenType = typeof(DerivedJwtSecurityToken)
            };

            JwtSecurityToken jwt =
                new JwtSecurityToken
                (
                    issuer: Issuers.GotJwt,
                    audience: Audiences.AuthFactors,
                    claims: ClaimSets.Simple(Issuers.GotJwt, Issuers.GotJwt),
                    signingCredentials: KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                    expires: DateTime.UtcNow + TimeSpan.FromHours(10),
                    notBefore: DateTime.UtcNow
                );

            string encodedJwt = handler.WriteToken(jwt);
            TokenValidationParameters tvp = new TokenValidationParameters()
            {
                IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
                ValidateAudience = false,
                ValidIssuer = Issuers.GotJwt,
            };

            List<string> errors = new List<string>();
            ValidateDerived(encodedJwt, handler, tvp, ExpectedException.NoExceptionExpected, errors);
        }

        private void ValidateDerived(string jwt, DerivedJwtSecurityTokenHandler handler, TokenValidationParameters validationParameters, ExpectedException expectedException, List<string> errors)
        {
            try
            {
                SecurityToken validatedToken;
                handler.ValidateToken(jwt, validationParameters, out validatedToken);
                if ((handler.Jwt as DerivedJwtSecurityToken) == null)
                    errors.Add("(handler.Jwt as DerivedJwtSecurityToken) == null");

                if (!handler.ReadTokenCalled)
                    errors.Add("!handler.ReadTokenCalled");

                if (!handler.ValidateAudienceCalled)
                    errors.Add("!handler.ValidateAudienceCalled");

                if (!handler.ValidateIssuerCalled)
                    errors.Add("!handler.ValidateIssuerCalled");

                if (!handler.ValidateIssuerSigningKeyCalled)
                    errors.Add("!handler.ValidateIssuerSigningKeyCalled");

                if (!handler.ValidateLifetimeCalled)
                    errors.Add("!handler.ValidateLifetimeCalled");

                if (!handler.ValidateSignatureCalled)
                    errors.Add("!handler.ValidateSignatureCalled");

                expectedException.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex, errors);
            }
        }

#if BREAKING
        // NamedKeySecurityKeyIdentifierClause gone
        [Fact(DisplayName = "Extensibility tests for NamedKeySecurityKeyIdentifierClause")]
        public void NamedKeySecurityKeyIdentifierClause_Extensibility()
        {
            string clauseName = "kid";
            string keyId = Issuers.GotJwt;

            NamedKeySecurityKeyIdentifierClause clause = new NamedKeySecurityKeyIdentifierClause(clauseName, keyId);
            SecurityKeyIdentifier keyIdentifier = new SecurityKeyIdentifier(clause);
            SigningCredentials signingCredentials = new SigningCredentials(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest, keyIdentifier);
            JwtHeader jwtHeader = new JwtHeader(signingCredentials);
            SecurityKeyIdentifier ski = jwtHeader.SigningKeyIdentifier;
            Assert.Equal(ski.Count, 1, "ski.Count != 1 ");

            NamedKeySecurityKeyIdentifierClause clauseOut = ski.Find<NamedKeySecurityKeyIdentifierClause>();
            Assert.IsNotNull(clauseOut, "NamedKeySecurityKeyIdentifierClause not found");
            Assert.Equal(clauseOut.Name, clauseName, "clauseOut.Id != clauseId");
            Assert.Equal(clauseOut.Id, keyId, "clauseOut.KeyIdentifier != keyId");

            NamedKeySecurityToken NamedKeySecurityToken = new NamedKeySecurityToken(clauseName, keyId, new SecurityKey[] { KeyingMaterial.DefaultSymmetricSecurityKey_256 });
            ((NamedKeySecurityToken.MatchesKeyIdentifierClause(clause), "NamedKeySecurityToken.MatchesKeyIdentifierClause( clause ), failed");

            List<SecurityKey> list = new List<SecurityKey>() { KeyingMaterial.DefaultSymmetricSecurityKey_256 };
            Dictionary<string, IList<SecurityKey>> keys = new Dictionary<string, IList<SecurityKey>>() { { "kid", list }, };
            NamedKeyIssuerTokenResolver nkitr = new NamedKeyIssuerTokenResolver(keys: keys);
            SecurityKey sk = nkitr.ResolveSecurityKey(clause);
            Assert.IsNotNull(sk, "NamedKeySecurityToken.MatchesKeyIdentifierClause( clause ), failed");
        }
#endif

        [Fact(DisplayName = "ExtensibilityTests: Algorithm names can be mapped inbound and outbound (AsymmetricSignatureProvider)")]
        public void AsymmetricSignatureProvider_Extensibility()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            string newAlgorithmValue = "bobsYourUncle";

            string originalAlgorithmValue = ReplaceAlgorithm(SecurityAlgorithms.RsaSha256Signature, newAlgorithmValue, JwtSecurityTokenHandler.OutboundAlgorithmMap);
            JwtSecurityToken jwt = handler.CreateToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, signingCredentials: KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2) as JwtSecurityToken;
            ReplaceAlgorithm(SecurityAlgorithms.RsaSha256Signature, originalAlgorithmValue, JwtSecurityTokenHandler.OutboundAlgorithmMap);
            //System.Diagnostics.Debugger.Launch();
            // outbound mapped algorithm is "bobsYourUncle", inbound map will not find this
            ExpectedException expectedException = ExpectedException.SecurityTokenInvalidSignatureException(substringExpected: "IDX10503:");
            RunAlgorithmMappingTest(jwt.RawData, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, handler, expectedException);

            // "bobsYourUncle" is mapped to RsaSha256
            originalAlgorithmValue = ReplaceAlgorithm(newAlgorithmValue, SecurityAlgorithms.RsaSha256Signature, JwtSecurityTokenHandler.InboundAlgorithmMap);
            RunAlgorithmMappingTest(jwt.RawData, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, handler, ExpectedException.NoExceptionExpected);
            ReplaceAlgorithm(newAlgorithmValue, originalAlgorithmValue, JwtSecurityTokenHandler.InboundAlgorithmMap);
        }

#if SymmetricKeySuport
        [Fact(DisplayName = "ExtensibilityTests: Algorithm names can be mapped inbound and outbound (SymmetricSignatureProvider)")]
        public void SymmetricSignatureProvider_Extensibility()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            string newAlgorithmValue = "bobsYourUncle";

            string originalAlgorithmValue = ReplaceAlgorithm(SecurityAlgorithms.HmacSha256Signature, newAlgorithmValue, JwtSecurityTokenHandler.OutboundAlgorithmMap);
            JwtSecurityToken jwt = handler.CreateToken(issuer: IdentityUtilities.DefaultIssuer, audience: IdentityUtilities.DefaultAudience, signingCredentials: KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2) as JwtSecurityToken;
            ReplaceAlgorithm(SecurityAlgorithms.HmacSha256Signature, originalAlgorithmValue, JwtSecurityTokenHandler.OutboundAlgorithmMap);

            // outbound mapped algorithm is "bobsYourUncle", inbound map will not find this
            ExpectedException expectedException = ExpectedException.SignatureVerificationFailedException(innerTypeExpected: typeof(InvalidOperationException), substringExpected: "IDX10503:");
            RunAlgorithmMappingTest(jwt.RawData, IdentityUtilities.DefaultSymmetricTokenValidationParameters, handler, expectedException);

            // inbound is mapped Hmac
            originalAlgorithmValue = ReplaceAlgorithm(newAlgorithmValue, SecurityAlgorithms.HmacSha256Signature, JwtSecurityTokenHandler.InboundAlgorithmMap);
            RunAlgorithmMappingTest(jwt.RawData, IdentityUtilities.DefaultSymmetricTokenValidationParameters, handler, ExpectedException.NoExceptionExpected);
            ReplaceAlgorithm(newAlgorithmValue, originalAlgorithmValue, JwtSecurityTokenHandler.InboundAlgorithmMap);
        }
#endif
        private void RunAlgorithmMappingTest(string jwt, TokenValidationParameters validationParameters, JwtSecurityTokenHandler handler, ExpectedException expectedException)
        {
            try
            {
                SecurityToken validatedToken;
                handler.ValidateToken(jwt, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        private string ReplaceAlgorithm(string algorithmKey, string newAlgorithmValue, IDictionary<string, string> algorithmMap)
        {
            string originalAlgorithmValue = null;
            if (algorithmMap.TryGetValue(algorithmKey, out originalAlgorithmValue))
            {
                algorithmMap.Remove(algorithmKey);
            }

            if (!string.IsNullOrWhiteSpace(newAlgorithmValue))
            {
                algorithmMap.Add(algorithmKey, newAlgorithmValue);
            }

            return originalAlgorithmValue;
        }
    }
}
