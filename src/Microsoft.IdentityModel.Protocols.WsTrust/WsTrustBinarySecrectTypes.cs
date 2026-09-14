// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants: WS-Trust BinarySecrectTypes.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Gets WS-Trust Feb2005 BinarySecrectTypes.
        /// </summary>
        public static WsTrustFeb2005BinarySecretTypes TrustFeb2005 { get; } = new WsTrustFeb2005BinarySecretTypes();

        /// <summary>
        /// Gets WS-Trust 1.3 BinarySecrectTypes.
        /// </summary>
        public static WsTrust13BinarySecretTypes Trust13 { get; } = new WsTrust13BinarySecretTypes();

        /// <summary>
        /// Gets WS-Trust 1.4 BinarySecrectTypes.
        /// </summary>
        public static WsTrust14BinarySecretTypes Trust14 { get; } = new WsTrust14BinarySecretTypes();

        /// <summary>
        /// Gets AsymmetricKey BinarySecrectType.
        /// </summary>
        public string AsymmetricKey { get; protected set; }

        /// <summary>
        /// Gets Nonce BinarySecrectType.
        /// </summary>
        public string Nonce { get; protected set; }

        /// <summary>
        /// Gets SymmetricKey BinarySecrectType.
        /// </summary>
        public string SymmetricKey { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Trust Feb2005 BinarySecretTypes.
    /// </summary>
    public class WsTrustFeb2005BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates WS-Trust Feb2005 BinarySecretTypes.
        /// </summary>
        public WsTrustFeb2005BinarySecretTypes()
        {
            AsymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/AsymmetricKey";
            Nonce = "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce";
            SymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.3 BinarySecretTypes.
    /// </summary>
    public class WsTrust13BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates WS-Trust 1.3 BinarySecretTypes.
        /// </summary>
        public WsTrust13BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }

    /// <summary>
    /// Constants: WS-Trust 1.4 BinarySecretTypes.
    /// </summary>
    /// <remarks>
    /// WS-Trust 1.4 is an addendum to 1.3 and does not define its own BinarySecretTypeEnum.
    /// The 1.4 schema declares targetNamespace='http://docs.oasis-open.org/ws-sx/ws-trust/200802'
    /// but imports the core types with xmlns:wst='http://docs.oasis-open.org/ws-sx/ws-trust/200512',
    /// adding only the interactive challenge elements. The BinarySecret/@Type values therefore
    /// remain in the 200512 namespace, as do the 1.4 action and key type URIs.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust-1.4.xsd </para>
    /// </remarks>
    public class WsTrust14BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates WS-Trust 1.4 BinarySecretTypes.
        /// </summary>
        public WsTrust14BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}
