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
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Claims;

using SamlHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;
using Saml2Handler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;

namespace Microsoft.IdentityModel.Extensions
{
    /// <summary>
    /// Extensions to <see cref="SecurityTokenHandler"/> that provide support for validating a security token
    /// passed as a string and using <see cref="TokenValidationParameters"/>.
    /// </summary>
    public static class SecurityTokenHandlerCollectionExtensions
    {
        /// <summary>
        /// Validates a token passed as a string using <see cref="TokenValidationParameters"/>
        /// </summary>
        /// <param name="tokenHandlers"><see cref="SecurityTokenHandlerCollection"/> uses extensions for <see cref="SecurityTokenHandler"/>(s) that can 
        /// validate from a string.</param>
        /// <param name="securityToken">token to validate.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> that contain necessary validation coordinates.</param>
        /// <exception cref="ArgumentNullException">'tokenHandlers' is null.</exception>
        /// <exception cref="ArgumentNullException">'securityToken' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> that represents the identity created when validating the token.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720")]
        public static ClaimsPrincipal ValidateToken(this SecurityTokenHandlerCollection tokenHandlers, string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (tokenHandlers == null)
            {
                throw new ArgumentNullException("tokenHandlers");
            }

            if (securityToken == null)
            {
                throw new ArgumentNullException("securityToken");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            bool iSecurityTokenValidatorFound = false;
            foreach (SecurityTokenHandler tokenHandler in tokenHandlers)
            {
                ISecurityTokenValidator securityTokenValidator = tokenHandler as ISecurityTokenValidator;
                if (securityTokenValidator != null && securityTokenValidator.CanReadToken(securityToken))
                {
                    iSecurityTokenValidatorFound = true;
                    return securityTokenValidator.ValidateToken(securityToken, validationParameters, out validatedToken);
                }
            }

            if (iSecurityTokenValidatorFound)
            {
                throw new SecurityTokenValidationException(ErrorMessages.IDX10201);
            }
            else
            {
                throw new SecurityTokenValidationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10201, securityToken));
            }
        }

        /// <summary>
        /// Gets the default <see cref="SecurityTokenHandlerCollection"/> supported by this runtime.
        /// </summary>
        /// <returns>A collection of <see cref="SecurityTokenHandler"/></returns>
        public static SecurityTokenHandlerCollection GetDefaultHandlers()
        {
            return new SecurityTokenHandlerCollection
            {
                new JwtSecurityTokenHandler(),
                new Saml2Handler(),
                new SamlHandler(),
            };
        }
    }
}