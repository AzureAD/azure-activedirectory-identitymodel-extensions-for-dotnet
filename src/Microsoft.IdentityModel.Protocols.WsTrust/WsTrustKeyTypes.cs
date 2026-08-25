// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants: WS-Trust KeyTypes.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustKeyTypes
    {
        /// <summary>
        /// Gets WS-Trust Feb2005 KeyTypes.
        /// </summary>
        public static WsTrustFeb2005KeyTypes TrustFeb2005 { get; } = new WsTrustFeb2005KeyTypes();

        /// <summary>
        /// Gets WS-Trust 1.3 KeyTypes.
        /// </summary>
        public static WsTrust13KeyTypes Trust13 { get; } = new WsTrust13KeyTypes();

        /// <summary>
        /// Gets WS-Trust 1.4 KeyTypes.
        /// </summary>
        public static WsTrust14KeyTypes Trust14 { get; } = new WsTrust14KeyTypes();

        /// <summary>
        /// Gets Bearer KeyType.
        /// </summary>
        public string Bearer { get; protected set; }

        /// <summary>
        /// Gets PublicKey KeyType.
        /// </summary>
        public string PublicKey { get; protected set; }

        /// <summary>
        /// Gets PSHA1 KeyType.
        /// </summary>
        public string PSHA1 { get; protected set; }

        /// <summary>
        /// Gets Symmetric KeyType.
        /// </summary>
        public string Symmetric { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Trust Feb2005 KeyTypes.
    /// </summary>
    public class WsTrustFeb2005KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates WS-Trust Feb2005 KeyTypes.
        /// </summary>
        public WsTrustFeb2005KeyTypes()
        {
            Bearer = "http://schemas.xmlsoap.org/ws/2005/02/trust/Bearer";
            PSHA1 = "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1";
            PublicKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey";
            Symmetric = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.3 KeyTypes.
    /// </summary>
    public class WsTrust13KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates WS-Trust 1.3 KeyTypes.
        /// </summary>
        public WsTrust13KeyTypes()
        {
            Bearer = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            PSHA1 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";
            PublicKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            Symmetric = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"; ;
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.4 KeyTypes.
    /// </summary>
    public class WsTrust14KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates WS-Trust 1.4 KeyTypes.
        /// </summary>
        public WsTrust14KeyTypes()
        {
            Bearer = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            PSHA1 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";
            PublicKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            Symmetric = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}
