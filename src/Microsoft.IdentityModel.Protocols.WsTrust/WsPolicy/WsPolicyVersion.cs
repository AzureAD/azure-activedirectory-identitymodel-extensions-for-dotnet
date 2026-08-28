// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Types for identifying a version of WS-Policy.
    /// These are used by the <see cref="WsTrustSerializer"/> to identify the version of WS-Policy to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    internal abstract class WsPolicyVersion
    {
        /// <summary>
        /// Identifies WS-Policy 1.2.
        /// </summary>
        public static WsPolicyVersion Policy12 { get; } = new WsPolicy12Version();

        /// <summary>
        /// Identifies WS-Policy 1.5.
        /// </summary>
        public static WsPolicyVersion Policy15 { get; } = new WsPolicy15Version();
    }

    /// <summary>
    /// Type identifying WS-Policy 1.2.
    /// </summary>
    internal class WsPolicy12Version : WsPolicyVersion { }

    /// <summary>
    /// Type identifying WS-Policy 1.5.
    /// </summary>
    internal class WsPolicy15Version : WsPolicyVersion { }
}
