// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Constants: WS-Policy attribute names.
    /// <para>see: http://specs.xmlsoap.org/ws/2004/09/policy/ws-policy.pdf </para>
    /// </summary>
    public static class WsPolicyAttributes
    {
        /// <summary>
        /// Gets the value for "Digest"
        /// </summary>
        public const string Digest = "Digest";

        /// <summary>
        /// Gets the value for "DigestAlgorithm"
        /// </summary>
        public const string DigestAlgorithm = "DigestAlgorithm";

        /// <summary>
        /// Gets the value for "Optional"
        /// </summary>
        public const string Optional = "Optional";

        /// <summary>
        /// Gets the value for "PolicyURIs"
        /// </summary>
        public const string PolicyURIs = "PolicyURIs";

        /// <summary>
        /// Gets the value for "TargetNamespace"
        /// </summary>
        public const string TargetNamespace = "TargetNamespace";

        /// <summary>
        /// Gets the value for "URI"
        /// </summary>
        public const string URI = "URI";
    }
}
