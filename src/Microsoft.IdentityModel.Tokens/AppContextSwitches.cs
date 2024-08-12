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
        /// Enables a new behavior of using <see cref="CaseSensitiveClaimsIdentity"/> instead of <see cref="ClaimsIdentity"/> globally.
        /// </summary>
        internal const string UseCaseSensitiveClaimsIdentityTypeSwitch = "Microsoft.IdentityModel.Tokens.UseCaseSensitiveClaimsIdentityType";

        private static bool? _useCaseSensitiveClaimsIdentityType;

        internal static bool UseCaseSensitiveClaimsIdentityType => _useCaseSensitiveClaimsIdentityType ??= (AppContext.TryGetSwitch(UseCaseSensitiveClaimsIdentityTypeSwitch, out bool useCaseSensitiveClaimsIdentityType) && useCaseSensitiveClaimsIdentityType);

        /// <summary>
        /// When validating the issuer signing key, specifies whether to fail if the 'tid' claim is missing.
        /// </summary>
        internal const string DoNotFailOnMissingTidSwitch = "Switch.Microsoft.IdentityModel.DontFailOnMissingTidValidateIssuerSigning";

        private static bool? _doNotFailOnMissingTid;

        internal static bool DoNotFailOnMissingTid => _doNotFailOnMissingTid ??= (AppContext.TryGetSwitch(DoNotFailOnMissingTidSwitch, out bool doNotFailOnMissingTid) && doNotFailOnMissingTid);


        internal const string SkipValidationOfHmacKey = "Switch.Microsoft.IdentityModel.UnsafeRelaxHmacKeySizeValidation";

        private static bool? _skipValidationOfHmacKeySizes;

        internal static bool SkipValidationOfHmacKeySizes => _skipValidationOfHmacKeySizes ??= (AppContext.TryGetSwitch(SkipValidationOfHmacKey, out bool skipValidationOfHmacKeySizes) && skipValidationOfHmacKeySizes);

        /// <summary>
        /// Used for testing to reset all switches to its default value.
        /// </summary>
        internal static void ResetAllSwitches()
        {
            _useCaseSensitiveClaimsIdentityType = null;
            AppContext.SetSwitch(UseCaseSensitiveClaimsIdentityTypeSwitch, false);

            _doNotFailOnMissingTid = null;
            AppContext.SetSwitch(DoNotFailOnMissingTidSwitch, false);

            _skipValidationOfHmacKeySizes = null;
            AppContext.SetSwitch(SkipValidationOfHmacKey, false);
        }
#else
        // .NET 4.5 does not support AppContext switches. Always use ClaimsIdentity.
        internal static bool UseCaseSensitiveClaimsIdentityType() => false;
#endif
    }
}
