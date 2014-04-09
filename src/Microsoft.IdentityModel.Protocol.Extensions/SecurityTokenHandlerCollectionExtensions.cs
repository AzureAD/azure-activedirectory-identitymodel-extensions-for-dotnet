// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Claims;

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
        public static ClaimsPrincipal ValidateToken(this SecurityTokenHandlerCollection tokenHandlers, string securityToken, TokenValidationParameters validationParameters)
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
                    return securityTokenValidator.ValidateToken(securityToken, validationParameters);
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
            return GetDefaultHandlers(null);
        }
        /// <summary>
        /// Gets the default <see cref="SecurityTokenHandlerCollection"/> supported by this runtime.
        /// </summary>
        /// <param name="authenticationType"> Each <see cref="SecurityTokenHandler"/> will create each <see cref="ClaimsIdentity"/> with this authenticationType.</param>
        /// <returns>A collection of <see cref="SecurityTokenHandler"/></returns>
        public static SecurityTokenHandlerCollection GetDefaultHandlers(string authenticationType)
        {
            if (string.IsNullOrWhiteSpace(authenticationType))
            {
                return new SecurityTokenHandlerCollection
                {
                    new JwtSecurityTokenHandler{ AuthenticationType = AuthenticationTypes.Federation},
                    new SamlSecurityTokenHandler{ AuthenticationType = AuthenticationTypes.Federation},
                    new Saml2SecurityTokenHandler{ AuthenticationType = AuthenticationTypes.Federation},
                };
            }
            else
            {
                return new SecurityTokenHandlerCollection
                {
                    new JwtSecurityTokenHandler{ AuthenticationType = authenticationType},
                    new SamlSecurityTokenHandler{ AuthenticationType = authenticationType},
                    new Saml2SecurityTokenHandler{ AuthenticationType = authenticationType},
                };
            }
        }
    }
}