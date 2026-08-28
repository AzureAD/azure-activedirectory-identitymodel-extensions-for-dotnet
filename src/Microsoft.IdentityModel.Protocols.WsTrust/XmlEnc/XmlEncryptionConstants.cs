// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Constants: XML Encryption namespace and prefix.
    /// <para>see: https://www.w3.org/TR/xmlenc-core1/ </para>
    /// </summary>
    internal abstract class XmlEncryptionConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static readonly IList<string> KnownNamespaces = new List<string> { "http://www.w3.org/2001/04/xmlenc#" };

        /// <summary>
        /// Gets constants for XML Encryption 1.1
        /// </summary>
        public static XmlEncryption11Constants XmlEnc11 { get; } = new XmlEncryption11Constants();
    }

    /// <summary>
    /// Constants: XML Encryption 1.1 namespace and prefix.
    /// </summary>
    internal class XmlEncryption11Constants : XmlEncryptionConstants
    {
        /// <summary>
        /// Instantiates XML Encryption 1.1
        /// </summary>
        public XmlEncryption11Constants()
        {
            Namespace = "http://www.w3.org/2001/04/xmlenc#";
            Prefix = "xenc";
        }
    }
}
