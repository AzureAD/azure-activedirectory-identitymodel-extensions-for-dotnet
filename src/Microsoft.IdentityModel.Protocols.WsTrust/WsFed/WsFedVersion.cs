// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Types for identifying a version of WS-Federation.
    /// These are used by the <see cref="WsTrustSerializer"/> to identify the version of WS-Federation to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    internal abstract class WsFedVersion
    {
        /// <summary>
        /// Identifies WS-Federation 1.2.
        /// </summary>
        public static WsFedVersion Fed12 = new WsFed12Version();
    }

    /// <summary>
    /// Type identifying WS-Federation 1.2.
    /// </summary>
    internal class WsFed12Version : WsFedVersion { }
}
