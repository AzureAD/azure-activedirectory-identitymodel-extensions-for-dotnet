// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Constants: WS-Federation namespace and prefix.
    /// <para>see: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html </para>
    /// </summary>
    public abstract class WsFedConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://docs.oasis-open.org/wsfed/federation/200706" };

        /// <summary>
        /// Gets the list of auth namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownAuthNamespaces { get; } = new List<string> { "http://docs.oasis-open.org/wsfed/authorization/200706" };

        /// <summary>
        /// Gets constants for WS-Federation 1.2
        /// </summary>
        public static WsFed12Constants Fed12 { get; } = new WsFed12Constants();

        /// <summary>
        /// Gets the auth namespace for WS-Federation.
        /// </summary>
        public string AuthNamespace { get; protected set; }

        /// <summary>
        /// Gets the auth prefix for WS-Federation.
        /// </summary>
        public string AuthPrefix { get; protected set; }

        /// <summary>
        /// Gets the privacy namespace for WS-Federation.
        /// </summary>
        public string PrivacyNamespace { get; protected set; }

        /// <summary>
        /// Gets the privacy prefix for WS-Federation.
        /// </summary>
        public string PrivacyPrefix { get; protected set; }

        /// <summary>
        /// Gets the schema location for WS-Federation.
        /// </summary>
        public string SchemaLocation { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Federation 1.2 namespace and prefix.
    /// </summary>
    public class WsFed12Constants : WsFedConstants
    {
        /// <summary>
        /// Instantiates WS-Federation 1.2
        /// </summary>
        public WsFed12Constants()
        {
            AuthNamespace = "http://docs.oasis-open.org/wsfed/authorization/200706";
            AuthPrefix = "auth";
            Prefix = "fed";
            PrivacyNamespace = "http://docs.oasis-open.org/wsfed/privacy/200706";
            PrivacyPrefix = "priv";
            Namespace = "http://docs.oasis-open.org/wsfed/federation/200706";
            SchemaLocation = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3.xsd";
        }
    }
}
