// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Xml;

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Represents Xml Encryption EncryptedKey
    /// </summary>
    public class EncryptedKey
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public EncryptedKey()
        {
        }

        internal EncryptedKey(XmlElement sourceElement)
        {
            SourceElement = sourceElement;
        }

        internal XmlElement SourceElement { get; }
    }
}
