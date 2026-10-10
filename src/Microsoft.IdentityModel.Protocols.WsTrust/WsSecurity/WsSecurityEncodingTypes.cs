// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants: WS-Security EncodingTypes.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public abstract class WsSecurityEncodingTypes : WsConstantsBase
    {
        /// <summary>
        /// Gets WS-Security 1.0 EncodingTypes.
        /// </summary>
        public static WsSecurity10EncodingTypes WsSecurity10 { get; } = new WsSecurity10EncodingTypes();

        /// <summary>
        /// Gets WS-Security 1.1 EncodingTypes.
        /// </summary>
        public static WsSecurity11EncodingTypes WsSecurity11 { get; } = new WsSecurity11EncodingTypes();

        /// <summary>
        /// Gets Base64 EncodingType.
        /// </summary>
        public string Base64 { get; protected set; }

        /// <summary>
        /// Gets HexBinary EncodingType.
        /// </summary>
        public string HexBinary { get; protected set; }

        /// <summary>
        /// Gets Text EncodingType.
        /// </summary>
        public string Text { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Security 1.0 EncodingTypes.
    /// </summary>
    public class WsSecurity10EncodingTypes : WsSecurityEncodingTypes
    {
        /// <summary>
        /// Instantiates WS-Security 1.0 EncodingTypes.
        /// </summary>
        public WsSecurity10EncodingTypes()
        {
            Base64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#Base64Binary";
            HexBinary = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#HexBinary";
            Text = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#Text";
        }
    }

    /// <summary>
    /// Constants: WS-Security 1.1 EncodingTypes.
    /// </summary>
    public class WsSecurity11EncodingTypes : WsSecurityEncodingTypes
    {
        /// <summary>
        /// Instantiates WS-Security 1.1 EncodingTypes.
        /// </summary>
        public WsSecurity11EncodingTypes()
        {
            Base64 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#Base64Binary";
            HexBinary = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#HexBinary";
            Text = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#Text";
        }
    }
}
