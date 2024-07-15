// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// AppContext switches for Microsoft.IdentityModel.Tokens and referencing packages.
    /// </summary>
    internal static class AppContextSwitches
    {
        /// <summary>
        /// Enables a fallback to the previous behavior of using <see cref="ClaimsIdentity"/> instead of <see cref="CaseSensitiveClaimsIdentity"/> globally.
        /// </summary>
        internal const string UseCaseSensitiveClaimsIdentityTypeSwitch = "Microsoft.IdentityModel.Tokens.UseCaseSensitiveClaimsIdentityType";

#if NET46_OR_GREATER
        internal static bool UseCaseSensitiveClaimsIdentityType() => AppContext.TryGetSwitch(UseCaseSensitiveClaimsIdentityTypeSwitch, out bool useCaseSensitiveClaimsIdentityType) && useCaseSensitiveClaimsIdentityType;

#else
        // .NET 4.5 does not support AppContext switches. Always use ClaimsIdentity.
        internal static bool UseCaseSensitiveClaimsIdentityType() => false;
#endif
    }
}
