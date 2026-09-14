// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Constants: XML Encryption DataTypes.
    /// <para>see: https://www.w3.org/TR/xmlenc-core1/ </para>
    /// </summary>
    internal abstract class XmlEncryptionDataTypes
    {
        /// <summary>
        /// Gets XML Encryption 1.1 DataTypes.
        /// </summary>
        public static XmlEncryption11DataTypes XmlEnc11 { get; } = new XmlEncryption11DataTypes();

        /// <summary>
        /// Gets Content DataType.
        /// </summary>
        public string Content { get; protected set; }

        /// <summary>
        /// Gets Element DataType.
        /// </summary>
        public string Element { get; protected set; }
    }

    /// <summary>
    /// Constants: XML Encryption 1.1 DataTypes.
    /// </summary>
    internal class XmlEncryption11DataTypes : XmlEncryptionDataTypes
    {
        /// <summary>
        /// Instantiates DataTypes for XML Encryption 1.1.
        /// </summary>
        public XmlEncryption11DataTypes()
        {
            Content = "http://www.w3.org/2001/04/xmlenc#Content";
            Element = "http://www.w3.org/2001/04/xmlenc#Element";
        }
    }
}
