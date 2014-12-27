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

using Microsoft.IdentityModel.Extensions;
using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Xunit;
using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class SecurityTokenHandlerCollectionExtensionsTests
    {
        [Fact(DisplayName = "SecurityTokenHandlerCollectionExtensionsTests: Constructors")]
        public void Constructors()
        {
        }

        [Fact(DisplayName = "SecurityTokenHandlerCollectionExtensionsTests: Defaults")]
        public void Defaults()
        {
            SecurityTokenHandlerCollection securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            foreach (var tokenHandler in securityTokenValidators)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());
            }

            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            foreach (var tokenHandler in securityTokenValidators)
            {
                ISecurityTokenValidator tokenValidator = tokenHandler as ISecurityTokenValidator;
                Assert.IsNotNull(tokenValidator, "tokenHandler is not ISecurityTokenHandler, is" + tokenHandler.GetType().ToString());
            }
        }

        [Fact(DisplayName = "SecurityTokenHandlerCollectionExtensionsTests: GetSets")]
        public void GetSets()
        {
        }

        [Fact(DisplayName = "SecurityTokenHandlerCollectionExtensionsTests: Publics")]
        public void Publics()
        {
            SecurityTokenHandlerCollection securityTokenValidators = new SecurityTokenHandlerCollection();
            string defaultSamlToken = IdentityUtilities.CreateSamlToken();
            string defaultSaml2Token = IdentityUtilities.CreateSaml2Token();
            string defaultJwt = IdentityUtilities.DefaultAsymmetricJwt;

            ExpectedException expectedException = ExpectedException.ArgumentNullException("Parameter name: securityToken");
            ValidateToken(null, null, securityTokenValidators, expectedException);

            expectedException = ExpectedException.ArgumentNullException("Parameter name: validationParameters");
            ValidateToken(defaultSamlToken, null, securityTokenValidators, expectedException);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
            expectedException = ExpectedException.SecurityTokenValidationException("IDX10201");
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);

            securityTokenValidators = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            expectedException = ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037:");
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, expectedException);

            securityTokenValidators.Clear();
            securityTokenValidators.Add(new IMSamlTokenHandler());
            ValidateToken(defaultSamlToken, tokenValidationParameters, securityTokenValidators, ExpectedException.SignatureVerificationFailedException(substringExpected: "ID4037:"));
            ValidateToken(defaultSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.SecurityTokenValidationException(substringExpected: "IDX10201:"));
            securityTokenValidators.Add(new IMSaml2TokenHandler());
            securityTokenValidators.Add(new System.IdentityModel.Tokens.JwtSecurityTokenHandler());
            ValidateToken(defaultSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
            ValidateToken(defaultJwt, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, securityTokenValidators, ExpectedException.NoExceptionExpected);
        }

        private void ValidateToken(string securityToken, TokenValidationParameters validationParameters, SecurityTokenHandlerCollection tokenHandlers, ExpectedException expectedException)
        {
            try
            {
                SecurityToken validatedToken;
                tokenHandlers.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }
    }
}