// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Types for identifying a version of WS-Security.
    /// These are used by the <see cref="WsTrustSerializer"/> to identify the version of WS-Federation to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsSecurityVersion
    {
        /// <summary>
        /// Identifies WS-Security 1.0.
        /// </summary>

        public static WsSecurityVersion Security10 = new WsSecurity10Version();

        /// <summary>
        /// Identifies WS-Security 1.1.
        /// </summary>
        public static WsSecurityVersion Security11 = new WsSecurity11Version();
    }

    /// <summary>
    /// Type identifying WS-Security 10.
    /// </summary>
    internal class WsSecurity10Version : WsSecurityVersion { }

    /// <summary>
    /// Type identifying WS-Security 11.
    /// </summary>
    internal class WsSecurity11Version : WsSecurityVersion { }

}
