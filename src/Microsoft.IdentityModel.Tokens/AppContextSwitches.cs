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
        /// When reading claims from the token, specifies whether to try to convert all string claims to DateTime.
        /// Some claims are known not to be DateTime, so conversion is skipped.
        /// </summary>
        internal const string TryAllStringClaimsAsDateTimeSwitch = "Switch.Microsoft.IdentityModel.TryAllStringClaimsAsDateTime";

        private static bool? _tryAllStringClaimsAsDateTime;

        internal static bool TryAllStringClaimsAsDateTime => _tryAllStringClaimsAsDateTime ??= (AppContext.TryGetSwitch(TryAllStringClaimsAsDateTimeSwitch, out bool tryAsDateTime) && tryAsDateTime);

        /// <summary>
        /// Controls whether to validate the length of the authentication tag when decrypting a token.
        /// </summary>
        internal const string SkipValidationOfAuthenticationTagLengthSwitch = "Switch.Microsoft.IdentityModel.SkipAuthenticationTagLengthValidation";

        private static bool? _skipValidationOfAuthenticationTagLength;

        internal static bool ShouldValidateAuthenticationTagLength => _skipValidationOfAuthenticationTagLength ??= !(AppContext.TryGetSwitch(SkipValidationOfAuthenticationTagLengthSwitch, out bool skipValidation) && skipValidation);

        /// <summary>
        /// Controls whether to use the short name for the RSA OAEP key wrap algorithm.
        /// </summary>
        internal const string UseShortNameForRsaOaepKeySwitch = "Switch.Microsoft.IdentityModel.UseShortNameForRsaOaepKey";

        private static bool? _useShortNameForRsaOaepKey;

        internal static bool ShouldUseShortNameForRsaOaepKey => _useShortNameForRsaOaepKey ??= AppContext.TryGetSwitch(UseShortNameForRsaOaepKeySwitch, out var useKeyWrap) && useKeyWrap;

        /// <summary>
        /// Used for testing to reset all switches to its default value.
        /// </summary>
        internal static void ResetAllSwitches()
        {
            _useClaimsIdentityType = null;
            AppContext.SetSwitch(UseClaimsIdentityTypeSwitch, false);

            _doNotFailOnMissingTid = null;
            AppContext.SetSwitch(DoNotFailOnMissingTidSwitch, false);

            _tryAllStringClaimsAsDateTime = null;
            AppContext.SetSwitch(TryAllStringClaimsAsDateTimeSwitch, false);

            _skipValidationOfAuthenticationTagLength = null;
            AppContext.SetSwitch(SkipValidationOfAuthenticationTagLengthSwitch, false);

            _useShortNameForRsaOaepKey = null;
            AppContext.SetSwitch(UseShortNameForRsaOaepKeySwitch, false);
        }
#else
        // .NET 4.5 does not support AppContext switches. Always use ClaimsIdentity.
        internal static bool UseCaseSensitiveClaimsIdentityType() => false;
#endif
    }
}
