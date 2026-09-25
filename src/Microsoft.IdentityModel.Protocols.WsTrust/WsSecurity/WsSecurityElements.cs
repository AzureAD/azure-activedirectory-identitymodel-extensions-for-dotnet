// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants: WS-Security element names.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public static class WsSecurityElements
    {
        /// <summary>
        /// Gets the value for "BinarySecurityToken"
        /// </summary>
        public const string BinarySecurityToken = "BinarySecurityToken";

        /// <summary>
        /// Gets the value for "Created"
        /// </summary>
        public const string Created = "Created";

        /// <summary>
        /// Gets the value for "EncryptedHeader"
        /// </summary>
        public const string EncryptedHeader = "EncryptedHeader";

        /// <summary>
        /// Gets the value for "KeyIdentifier"
        /// </summary>
        public const string KeyIdentifier = "KeyIdentifier";

        /// <summary>
        /// Gets the value for "Nonce"
        /// </summary>
        public const string Nonce = "Nonce";

        /// <summary>
        /// Gets the value for "Password"
        /// </summary>
        public const string Password = "Password";

        /// <summary>
        /// Gets the value for "Reference"
        /// </summary>
        public const string Reference = "Reference";

        /// <summary>
        /// Gets the value for "SecurityTokenReference"
        /// </summary>
        public const string SecurityTokenReference = "SecurityTokenReference";

        /// <summary>
        /// Gets the value for "Username"
        /// </summary>
        public const string Username = "Username";

        /// <summary>
        /// Gets the value for "UsernameToken"
        /// </summary>
        public const string UsernameToken = "UsernameToken";
    }
}
