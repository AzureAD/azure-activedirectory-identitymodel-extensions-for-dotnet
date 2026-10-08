// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Types for identifying a version of WS-Addressing.
    /// These are passed to the <see cref="WsTrustSerializer"/> to identify the version of WsTrust to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsAddressingVersion
    {
        /// <summary>
        /// Identifies WS-Addressing 1.0.
        /// </summary>
        public static WsAddressingVersion Addressing10 = new WsAddressing10Version();

        /// <summary>
        /// Identifies WS-Addressing 200408
        /// </summary>
        public static WsAddressingVersion Addressing200408 = new WsAddressing200408Version();
    }

    /// <summary>
    /// Type identifying  WS-Addressing 1.0.
    /// </summary>
    public class WsAddressing10Version : WsAddressingVersion { }

    /// <summary>
    /// Type identifying WS-Addressing 200408.
    /// </summary>
    public class WsAddressing200408Version : WsAddressingVersion { }
}
