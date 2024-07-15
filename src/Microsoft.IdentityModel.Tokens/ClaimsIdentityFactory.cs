// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Facilitates the creation of <see cref="ClaimsIdentity"/> and <see cref="CaseSensitiveClaimsIdentity"/> instances based on the <see cref="AppContextSwitches.UseCaseSensitiveClaimsIdentityTypeSwitch"/>.
    /// </summary>
    internal static class ClaimsIdentityFactory
    {
        internal static ClaimsIdentity Create(IEnumerable<Claim> claims)
        {
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
                return new CaseSensitiveClaimsIdentity(claims);

            return new ClaimsIdentity(claims);
        }

        internal static ClaimsIdentity Create(IEnumerable<Claim> claims, string authenticationType)
        {
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
                return new CaseSensitiveClaimsIdentity(claims, authenticationType);

            return new ClaimsIdentity(claims, authenticationType);
        }

        internal static ClaimsIdentity Create(string authenticationType, string nameType, string roleType, SecurityToken securityToken)
        {
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
                return new CaseSensitiveClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType)
                {
                    SecurityToken = securityToken,
                };

            return new ClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType);
        }

        internal static ClaimsIdentity Create(SecurityToken securityToken, TokenValidationParameters validationParameters, string issuer)
        {
            ClaimsIdentity claimsIdentity = validationParameters.CreateClaimsIdentity(securityToken, issuer);

            // Set the SecurityToken in cases where derived TokenValidationParameters created a CaseSensitiveClaimsIdentity.
            if (claimsIdentity is CaseSensitiveClaimsIdentity caseSensitiveClaimsIdentity && caseSensitiveClaimsIdentity.SecurityToken == null)
            {
                caseSensitiveClaimsIdentity.SecurityToken = securityToken;
            }
            else if (claimsIdentity is not CaseSensitiveClaimsIdentity && AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
            {
                claimsIdentity = new CaseSensitiveClaimsIdentity(claimsIdentity)
                {
                    SecurityToken = securityToken,
                };
            }

            return claimsIdentity;
        }

        internal static ClaimsIdentity Create(TokenHandler tokenHandler, SecurityToken securityToken, TokenValidationParameters validationParameters, string issuer)
        {
            ClaimsIdentity claimsIdentity = tokenHandler.CreateClaimsIdentityInternal(securityToken, validationParameters, issuer);

            // Set the SecurityToken in cases where derived TokenHandler created a CaseSensitiveClaimsIdentity.
            if (claimsIdentity is CaseSensitiveClaimsIdentity caseSensitiveClaimsIdentity && caseSensitiveClaimsIdentity.SecurityToken == null)
            {
                caseSensitiveClaimsIdentity.SecurityToken = securityToken;
            }
            else if (claimsIdentity is not CaseSensitiveClaimsIdentity && AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
            {
                claimsIdentity = new CaseSensitiveClaimsIdentity(claimsIdentity)
                {
                    SecurityToken = securityToken,
                };
            }

            return claimsIdentity;
        }
    }
}
