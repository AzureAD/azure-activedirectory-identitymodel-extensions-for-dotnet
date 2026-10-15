// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Constants: WS-Policy elements names.
    /// <para>see: http://specs.xmlsoap.org/ws/2004/09/policy/ws-policy.pdf </para>
    /// </summary>
    public static class WsPolicyElements
    {
        /// <summary>
        /// Gets the value for "All"
        /// </summary>
        public const string All = "All";

        /// <summary>
        /// Gets the value for "AppliesTo"
        /// </summary>
        public const string AppliesTo = "AppliesTo";

        /// <summary>
        /// Gets the value for "ExactlyOne"
        /// </summary>
        public const string ExactlyOne = "ExactlyOne";

        /// <summary>
        /// Gets the value for "Policy"
        /// </summary>
        public const string Policy = "Policy";

        /// <summary>
        /// Gets the value for "PolicyReference"
        /// </summary>
        public const string PolicyReference = "PolicyReference";
    }
}
