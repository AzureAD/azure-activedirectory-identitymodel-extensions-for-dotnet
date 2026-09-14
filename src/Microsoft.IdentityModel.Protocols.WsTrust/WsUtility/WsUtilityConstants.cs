// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsUtility
{
    /// <summary>
    /// Constants: WS-Utility namespace and prefix.
    /// <para>see: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd </para>
    /// </summary>
    public abstract class WsUtilityConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" };

        /// <summary>
        /// Gets constants for WS-Utility 1.0
        /// </summary>
        public static WsUtility10Constants WsUtility10 { get; } = new WsUtility10Constants();
    }

    /// <summary>
    /// Constants: WS-Utility 1.0 namespace and prefix.
    /// </summary>
    public class WsUtility10Constants : WsUtilityConstants
    {
        /// <summary>
        /// Instantiates WS-Utility 1.0
        /// </summary>
        public WsUtility10Constants()
        {
            Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            Prefix = "wsu";
        }
    }
}
