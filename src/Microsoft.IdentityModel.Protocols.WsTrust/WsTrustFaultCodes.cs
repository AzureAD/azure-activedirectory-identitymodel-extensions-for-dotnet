// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants: WS-Trust FaultCodes.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public static class WsTrustFaultCodes
    {
        /// <summary>
        /// Gets the value for "FailedAuthentication"
        /// </summary>
        public const string FailedAuthentication = "FailedAuthentication";

        /// <summary>
        /// Gets the value for "FailedCheck"
        /// </summary>
        public const string FailedCheck = "FailedCheck";

        /// <summary>
        /// Gets the value for "InvalidSecurity"
        /// </summary>
        public const string InvalidSecurity = "InvalidSecurity";

        /// <summary>
        /// Gets the value for "InvalidSecurityToken"
        /// </summary>
        public const string InvalidSecurityToken = "InvalidSecurityToken";

        /// <summary>
        /// Gets the value for "MessageExpired"
        /// </summary>
        public const string MessageExpired = "MessageExpired";

        /// <summary>
        /// Gets the value for "SecurityTokenUnavailable"
        /// </summary>
        public const string SecurityTokenUnavailable = "SecurityTokenUnavailable";

        /// <summary>
        /// Gets the value for "UnsupportedAlgorithm"
        /// </summary>
        public const string UnsupportedAlgorithm = "UnsupportedAlgorithm";

        /// <summary>
        /// Gets the value for "UnsupportedSecurityToken"
        /// </summary>
        public const string UnsupportedSecurityToken = "UnsupportedSecurityToken";
    }
}
