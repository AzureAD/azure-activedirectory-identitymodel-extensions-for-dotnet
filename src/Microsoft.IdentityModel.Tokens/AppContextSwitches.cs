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
#if NET461_OR_GREATER || NETCOREAPP || NETSTANDARD
        /// <summary>
        /// Enables a fallback to the previous behavior of using <see cref="ClaimsIdentity"/> instead of <see cref="CaseSensitiveClaimsIdentity"/> globally.
        /// </summary>
        internal const string UseClaimsIdentityTypeSwitch = "Microsoft.IdentityModel.Tokens.UseClaimsIdentityType";

        private static bool? _useClaimsIdentityType;

        internal static bool UseClaimsIdentityType => _useClaimsIdentityType ??= (AppContext.TryGetSwitch(UseClaimsIdentityTypeSwitch, out bool useClaimsIdentityType) && useClaimsIdentityType);

        /// <summary>
        /// When validating the issuer signing key, specifies whether to fail if the 'tid' claim is missing.
        /// </summary>
        internal const string DoNotFailOnMissingTidSwitch = "Switch.Microsoft.IdentityModel.DontFailOnMissingTidValidateIssuerSigning";

        private static bool? _doNotFailOnMissingTid;

        internal static bool DoNotFailOnMissingTid => _doNotFailOnMissingTid ??= (AppContext.TryGetSwitch(DoNotFailOnMissingTidSwitch, out bool doNotFailOnMissingTid) && doNotFailOnMissingTid);

        /// <summary>
        /// Used for testing to reset all switches to its default value.
        /// </summary>
        internal static void ResetAllSwitches()
        {
            _useClaimsIdentityType = null;
            AppContext.SetSwitch(UseClaimsIdentityTypeSwitch, false);

            _doNotFailOnMissingTid = null;
            AppContext.SetSwitch(DoNotFailOnMissingTidSwitch, false);
        }
#else
        // .NET 4.5 does not support AppContext switches. Always use ClaimsIdentity.
        internal static bool UseCaseSensitiveClaimsIdentityType() => false;
#endif
    }
}
