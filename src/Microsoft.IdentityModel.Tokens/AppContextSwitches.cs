﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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
        internal const string UseClaimsIdentityTypeSwitch = "Microsoft.IdentityModel.Tokens.UseClaimsIdentityType";

        private static bool? _useClaimsIdentity;

        internal static bool UseClaimsIdentityType => _useClaimsIdentity ??= (AppContext.TryGetSwitch(UseClaimsIdentityTypeSwitch, out bool useClaimsIdentityType) && useClaimsIdentityType);

        /// <summary>
        /// Used for testing to reset the <see cref="UseClaimsIdentityType"/> switch to its default value.
        /// </summary>
        internal static void ResetUseClaimsIdentityTypeSwitch()
        {
            _useClaimsIdentity = null;
            AppContext.SetSwitch(UseClaimsIdentityTypeSwitch, false);
        }

        /// <summary>
        /// When validating the issuer signing key, specifies whether to fail if the 'tid' claim is missing.
        /// </summary>
        internal const string DontFailOnMissingTidSwitch = "Switch.Microsoft.IdentityModel.DontFailOnMissingTidValidateIssuerSigning";

        private static bool? _dontFailOnMissingTid;

        internal static bool DontFailOnMissingTid => _dontFailOnMissingTid ??= (AppContext.TryGetSwitch(DontFailOnMissingTidSwitch, out bool dontFailOnMissingTid) && dontFailOnMissingTid);

        /// <summary>
        /// Used for testing to reset the <see cref="UseClaimsIdentityType"/> switch to its default value.
        /// </summary>
        internal static void ResetDontFailOnMissingTidSwitch()
        {
            _dontFailOnMissingTid = null;
            AppContext.SetSwitch(DontFailOnMissingTidSwitch, false);
        }

        /// <summary>
        /// When reading claims from the token, specifies whether to try to convert all string claims to DateTime.
        /// Some claims are known not to be DateTime, so conversion is skipped.
        /// </summary>
        internal const string TryAllStringClaimsAsDateTimeSwitch = "Switch.Microsoft.IdentityModel.TryAllStringClaimsAsDateTime";

        private static bool? _tryAllStringClaimsAsDateTime;

        internal static bool TryAllStringClaimsAsDateTime => _tryAllStringClaimsAsDateTime ??= (AppContext.TryGetSwitch(TryAllStringClaimsAsDateTimeSwitch, out bool tryAsDateTime) && tryAsDateTime);

        /// <summary>
        /// Used for testing to reset the <see cref="UseClaimsIdentityType"/> switch to its default value.
        /// </summary>
        internal static void ResetTryAllStringClaimsAsDateTimeSwitch()
        {
            _tryAllStringClaimsAsDateTime = null;
            AppContext.SetSwitch(TryAllStringClaimsAsDateTimeSwitch, false);
        }
    }
}
