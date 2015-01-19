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

using System;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Xunit;
using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;
using SMSaml2TokenHandler = System.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using SMSamlTokenHandler = System.IdentityModel.Tokens.SamlSecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// The purpose of these tests are to ensure that Saml, Saml2 and Jwt handling 
    /// results in the same exceptions, claims etc.
    /// </summary>
    public class CrossTokenTests
    {
        [Fact(DisplayName = "CrossTokenTests: Validates tokens")]
        public void CrossToken_ValidateToken()
        {
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            IMSaml2TokenHandler imSaml2Handler = new IMSaml2TokenHandler();
            IMSamlTokenHandler imSamlHandler = new IMSamlTokenHandler();
            SMSaml2TokenHandler smSaml2Handler = new SMSaml2TokenHandler();
            SMSamlTokenHandler smSamlHandler = new SMSamlTokenHandler();

            JwtSecurityTokenHandler.InboundClaimFilter.Add("aud");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("exp");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iat");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iss");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("nbf");

            string jwtToken = IdentityUtilities.CreateJwtToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, jwtHandler);

            // saml tokens created using Microsoft.IdentityModel.Extensions
            string imSaml2Token = IdentityUtilities.CreateSaml2Token(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, imSaml2Handler);
            string imSamlToken = IdentityUtilities.CreateSamlToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, imSamlHandler);

            // saml tokens created using System.IdentityModel.Tokens
            string smSaml2Token = IdentityUtilities.CreateSaml2Token(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, smSaml2Handler);
            string smSamlToken = IdentityUtilities.CreateSamlToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, smSamlHandler);

            ClaimsPrincipal jwtPrincipal = ValidateToken(jwtToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, jwtHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal imSaml2Principal = ValidateToken(imSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSaml2Handler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal imSamlPrincipal = ValidateToken(imSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSamlHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal smSaml2Principal = ValidateToken(smSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSaml2Handler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal smSamlPrincipal = ValidateToken(smSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSamlHandler, ExpectedException.NoExceptionExpected);

            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(imSamlPrincipal,  imSaml2Principal, new CompareContext { IgnoreSubject = true }));
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(smSamlPrincipal,  imSaml2Principal, new CompareContext { IgnoreSubject = true }));
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(smSaml2Principal, imSaml2Principal, new CompareContext { IgnoreSubject = true }));

            // false = ignore type of objects, we expect all objects in the principal to be of same type (no derived types)
            // true = ignore subject, claims have a backpointer to their ClaimsIdentity.  Most of the time this will be different as we are comparing two different ClaimsIdentities.
            // true = ignore properties of claims, any mapped claims short to long for JWT's will have a property that represents the short type.
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(jwtPrincipal, imSaml2Principal, new CompareContext{IgnoreType = false, IgnoreSubject = true, IgnoreProperties=true}));

            JwtSecurityTokenHandler.InboundClaimFilter.Clear();
        }

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, ISecurityTokenValidator tokenValidator, ExpectedException expectedException)
        {
            ClaimsPrincipal princiapl = null;
            try
            {
                SecurityToken validatedToken;
                princiapl = tokenValidator.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return princiapl;
        }


        [Fact(DisplayName = "CrossTokenTests: Validates Signatures")]
        public void CrossToken_ValidateSignature()
        {
            // ensure jwt, saml1 and saml2 work the same
        }

        [Fact(DisplayName = "CrossTokenTests: Validate Audience")]
        public void CrossToken_ValidateAudience()
        {
            // ensure jwt, saml1 and saml2 work the same
        }

        [Fact(DisplayName = "CrossTokenTests: Validate Issuer")]
        public void CrossToken_ValidateIssuer()
        {
            // ensure jwt, saml1 and saml2 work the same
        }

        [Fact(DisplayName = "CrossTokenTests: ValidateLifetime")]
        public void CrossToken_ValidateLifetime()
        {
            // ensure jwt, saml1 and saml2 work the same
        }
    }
}