// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants: WS-Security KeyTypes.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public abstract class WsSecurityKeyTypes
    {
        /// <summary>
        /// Gets key type constants for WS-Security 1.0
        /// </summary>
        public static WsSecurity10KeyTypes WsSecurity10 { get; } = new WsSecurity10KeyTypes();

        /// <summary>
        /// Gets key type constants for WS-Security 1.1
        /// </summary>
        public static WsSecurity11KeyTypes WsSecurity11 { get; } = new WsSecurity11KeyTypes();

        /// <summary>
        /// Gets Sha1Thumbprint constant type for WS-Security
        /// </summary>
        public string Sha1Thumbprint { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Security 1.0 KeyTypes.
    /// </summary>
    public class WsSecurity10KeyTypes : WsSecurityKeyTypes
    {
        /// <summary>
        /// Instantiates WS-Security 1.0 KeyTypes.
        /// </summary>
        public WsSecurity10KeyTypes()
        {
            Sha1Thumbprint = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#ThumbprintSHA1";
        }
    }

    /// <summary>
    /// Constants: WS-Security 1.1 KeyTypes.
    /// </summary>
    public class WsSecurity11KeyTypes : WsSecurityKeyTypes
    {
        /// <summary>
        /// Instantiates WS-Security 1.1 KeyTypes.
        /// </summary>
        public WsSecurity11KeyTypes()
        {
            Sha1Thumbprint = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#ThumbprintSHA1";
        }
    }
}
