// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    internal static class ClaimsIdentityFactory
    {
        internal static ClaimsIdentity Create(IEnumerable<Claim> claims)
        {
            if (AppContextSwitches.UseClaimsIdentityType())
                return new ClaimsIdentity(claims);

            return new CaseSensitiveClaimsIdentity(claims);
        }

        internal static ClaimsIdentity Create(IEnumerable<Claim> claims, string authenticationType)
        {
            if (AppContextSwitches.UseClaimsIdentityType())
                return new ClaimsIdentity(claims, authenticationType);

            return new CaseSensitiveClaimsIdentity(claims, authenticationType);
        }
    }
}
