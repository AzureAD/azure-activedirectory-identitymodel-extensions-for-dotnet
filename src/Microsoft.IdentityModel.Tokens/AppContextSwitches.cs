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
        /// Enables a new behavior of using <see cref="CaseSensitiveClaimsIdentity"/> instead of <see cref="ClaimsIdentity"/> globally.
        /// </summary>
        internal const string UseCaseSensitiveClaimsIdentityTypeSwitch = "Microsoft.IdentityModel.Tokens.UseCaseSensitiveClaimsIdentityType";

#if NET46_OR_GREATER || NETCOREAPP || NETSTANDARD
        internal static bool UseCaseSensitiveClaimsIdentityType() => AppContext.TryGetSwitch(UseCaseSensitiveClaimsIdentityTypeSwitch, out bool useCaseSensitiveClaimsIdentityType) && useCaseSensitiveClaimsIdentityType;

#else
        // .NET 4.5 does not support AppContext switches. Always use ClaimsIdentity.
        internal static bool UseCaseSensitiveClaimsIdentityType() => false;
#endif
    }
}
