// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Constants: WS-Addressing namespace and prefix.
    /// <para>see: https://www.w3.org/Submission/ws-addressing/ </para>
    /// </summary>
    public abstract class WsAddressingConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://www.w3.org/2005/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing" };

        /// <summary>
        /// Gets constants for WS-Addressing 1.0.
        /// </summary>
        public static WsAddressing10Constants Addressing10 { get; } = new WsAddressing10Constants();

        /// <summary>
        /// Gets constants for WS-Addressing 200408.
        /// </summary>
        public static WsAddressing200408Constants Addressing200408 { get; } = new WsAddressing200408Constants();
    }

    /// <summary>
    /// Constants: WS-Addressing 1.0 namespace and prefix.
    /// </summary>
    public class WsAddressing10Constants : WsAddressingConstants
    {
        /// <summary>
        /// Instantiates WS-Addressing 1.0
        /// </summary>
        public WsAddressing10Constants()
        {
            Namespace = "http://www.w3.org/2005/08/addressing";
            Prefix = "wsa";
        }
    }

    /// <summary>
    /// Constants: WS-Addressing 200408 namespace and prefix.
    /// </summary>
    public class WsAddressing200408Constants : WsAddressingConstants
    {
        /// <summary>
        /// Instantiates WS-Addressing 200408
        /// </summary>
        public WsAddressing200408Constants()
        {
            Namespace = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
            Prefix = "wsa";
        }
    }
}
