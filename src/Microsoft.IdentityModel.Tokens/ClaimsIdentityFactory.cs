// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
#if !NET45
    /// <summary>
    /// Facilitates the creation of <see cref="ClaimsIdentity"/> and <see cref="CaseSensitiveClaimsIdentity"/> instances based on the <see cref="AppContextSwitches.UseCaseSensitiveClaimsIdentityType"/>.
    /// </summary>
#endif

    internal static class ClaimsIdentityFactory
    {
        internal static ClaimsIdentity Create(IEnumerable<Claim> claims)
        {
#if NET45
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
#else
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType)
#endif
                return new CaseSensitiveClaimsIdentity(claims);

            return new ClaimsIdentity(claims);
        }

        internal static ClaimsIdentity Create(IEnumerable<Claim> claims, string authenticationType)
        {
#if NET45
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
#else
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType)
#endif
                return new CaseSensitiveClaimsIdentity(claims, authenticationType);

            return new ClaimsIdentity(claims, authenticationType);
        }

        internal static ClaimsIdentity Create(string authenticationType, string nameType, string roleType, SecurityToken securityToken)
        {
#if NET45
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType())
#else
            if (AppContextSwitches.UseCaseSensitiveClaimsIdentityType)
#endif
                return new CaseSensitiveClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType)
                {
                    SecurityToken = securityToken,
                };
            return new ClaimsIdentity(authenticationType: authenticationType, nameType: nameType, roleType: roleType);
        }
    }
}
