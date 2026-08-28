// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Types for identifying a version of WSTrust.
    /// These are used by the <see cref="WsTrustSerializer"/> to identify the version of WSTrust to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustVersion
    {
        /// <summary>
        /// Identifies WSTrust Feb2005.
        /// </summary>
        public static WsTrustVersion TrustFeb2005 = new WsTrustFeb2005Version();

        /// <summary>
        /// Identifies WSTrust 1.3.
        /// </summary>
        public static WsTrustVersion Trust13 = new WsTrust13Version();

        /// <summary>
        /// Identifies WSTrust 1.4.
        /// </summary>
        public static WsTrustVersion Trust14 = new WsTrust14Version();
    }

    /// <summary>
    /// Type identifying WSTrust Feb2005
    /// </summary>
    internal class WsTrustFeb2005Version : WsTrustVersion { }

    /// <summary>
    /// Type identifying WSTrust 1.3
    /// </summary>
    internal class WsTrust13Version : WsTrustVersion { }

    /// <summary>
    /// Type identifying WSTrust 1.4
    /// </summary>
    internal class WsTrust14Version : WsTrustVersion { }
}
