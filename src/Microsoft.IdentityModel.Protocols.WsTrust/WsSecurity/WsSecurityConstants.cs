// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants: WS-Security namespace and prefix.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public abstract class WsSecurityConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static readonly IList<string> KnownNamespaces = new List<string> { "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" };

        /// <summary>
        /// Gets constants for WS-Security 1.0.
        /// </summary>
        public static WsSecurity10Constants WsSecurity10 => new WsSecurity10Constants();

        /// <summary>
        /// Gets constants for WS-Security 1.1.
        /// </summary>
        public static WsSecurity11Constants WsSecurity11 => new WsSecurity11Constants();

        /// <summary>
        /// Gets FragmentBaseAddress for WS-Security.
        /// </summary>
        public string FragmentBaseAddress { get; protected set; }

        /// <summary>
        /// Gets EncodingTypes for WS-Security.
        /// </summary>
        public WsSecurityEncodingTypes EncodingTypes { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Security 1.0 namespace and prefix.
    /// </summary>
    public class WsSecurity10Constants : WsSecurityConstants
    {
        /// <summary>
        /// Instantiates WS-Security 1.0
        /// </summary>
        public WsSecurity10Constants()
        {
            EncodingTypes = WsSecurityEncodingTypes.WsSecurity10;
            FragmentBaseAddress = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";
            Prefix = "wsse";
            Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        }
    }

    /// <summary>
    /// Constants: WS-Security 1.1 namespace and prefix.
    /// </summary>
    public class WsSecurity11Constants : WsSecurityConstants
    {
        /// <summary>
        /// Instantiates WS-Security 1.1
        /// </summary>
        public WsSecurity11Constants()
        {
            EncodingTypes = WsSecurityEncodingTypes.WsSecurity11;
            FragmentBaseAddress = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";
            Namespace = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
            Prefix = "wsse11";
        }
    }
}
