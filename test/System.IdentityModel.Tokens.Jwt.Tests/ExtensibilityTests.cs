//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
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
            ExpectedException expectedException = ExpectedException.SecurityTokenInvalidSignatureException(innerTypeExpected: typeof(InvalidOperationException), substringExpected: "IDX10503:");
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
