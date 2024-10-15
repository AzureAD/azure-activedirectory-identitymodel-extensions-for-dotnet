﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable RS0030 // Do not use banned APIs

    /// <summary>
    /// Facilitates the creation of <see cref="ClaimsIdentity"/> and <see cref="CaseSensitiveClaimsIdentity"/> instances based on the <see cref="AppContextSwitches.UseClaimsIdentityTypeSwitch"/>.
    /// </summary>
    internal static class ClaimsIdentityFactory
    {
        internal static ClaimsIdentity Create(IEnumerable<Claim> claims)
        {
            if (AppContextSwitches.UseClaimsIdentityType)
                return new ClaimsIdentity(claims);

            return new CaseSensitiveClaimsIdentity(claims);
        }

        internal static ClaimsIdentity Create(IEnumerable<Claim> claims, string authenticationType)
        {
            if (AppContextSwitches.UseClaimsIdentityType)
                return new ClaimsIdentity(claims, authenticationType);

            return new CaseSensitiveClaimsIdentity(claims, authenticationType);
        }

        internal static ClaimsIdentity Create(string authenticationType, string nameType, string roleType, SecurityToken securityToken, TokenValidationParameters tokenValidationParameters)
        {
            if (AppContextSwitches.UseClaimsIdentityType)
                return new ClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType);

            if (tokenValidationParameters.UseNewClaimsIdentityType)
            {
                return new SecurityTokenClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType)
                {
                    SecurityToken = securityToken,
                };
            }
            else
            {
                return new CaseSensitiveClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType)
                {
                    SecurityToken = securityToken,
                };
            }
        }
    }

#pragma warning restore RS0030 // Do not use banned APIs
}
