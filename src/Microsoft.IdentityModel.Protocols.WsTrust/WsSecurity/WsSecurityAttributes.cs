// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants: WS-Security attribute names.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public static class WsSecurityAttributes
    {
        /// <summary>
        /// Gets the value for "EncodingType"
        /// </summary>
        public const string EncodingType = "EncodingType";

        /// <summary>
        /// Gets the value for "Id"
        /// </summary>
        public const string Id = "Id";

        // WsSecurity 1.1 {2004}
        /// <summary>
        /// Gets the value for "TokenType"
        /// </summary>
        public const string TokenType = "TokenType";

        /// <summary>
        /// Gets the value for "Type"
        /// </summary>
        public const string Type = "Type";

        /// <summary>
        /// Gets the value for "URI"
        /// </summary>
        public const string URI = "URI";

        /// <summary>
        /// Gets the value for "Usage"
        /// </summary>
        public const string Usage = "Usage";

        /// <summary>
        /// Gets the value for "ValueType"
        /// </summary>
        public const string ValueType = "ValueType";
    }
}
