// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Constants: WS-Policy constants namespace and prefix.
    /// <para>see: http://specs.xmlsoap.org/ws/2004/09/policy/ws-policy.pdf </para>
    /// </summary>
    public abstract class WsPolicyConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://schemas.xmlsoap.org/ws/2004/09/policy", "http://www.w3.org/ns/ws-policy" };

        /// <summary>
        /// Gets constants for WS-Policy 1.2
        /// </summary>
        public static WsPolicy12Constants Policy12 { get; } = new WsPolicy12Constants();

        /// <summary>
        /// Gets constants for WS-Policy 1.5
        /// </summary>
        public static WsPolicy15Constants Policy15 { get; } = new WsPolicy15Constants();
    }

    /// <summary>
    /// Constants: WS-Policy 1.2 namespace and prefix.
    /// </summary>
    public class WsPolicy12Constants : WsPolicyConstants
    {
        /// <summary>
        /// Instantiates WS-Policy 1.2
        /// </summary>
        public WsPolicy12Constants()
        {
            Namespace = "http://schemas.xmlsoap.org/ws/2004/09/policy";
            Prefix = "wsp";
        }
    }

    /// <summary>
    /// Constants: WS-Policy 1.5 namespace and prefix.
    /// </summary>
    public class WsPolicy15Constants : WsPolicyConstants
    {
        /// <summary>
        /// Instantiates WS-Policy 1.5
        /// </summary>
        public WsPolicy15Constants()
        {
            Namespace = "http://www.w3.org/ns/ws-policy";
            Prefix = "wsp";
        }
    }
}
