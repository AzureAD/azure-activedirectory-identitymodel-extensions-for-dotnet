//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the abstract base class from which the classes EncryptedData and EncryptedKey derive.
    /// </summary>
    /// <remarks>
    /// http://www.w3.org/TR/xmlenc-core1/#sec-EncryptedType
    /// </remarks>
    public abstract class EncryptedType
    {
        private CipherData _cipherData;
        private KeyInfo _keyInfo;
        private EncryptionMethod _encryptionMethod;

        /// <summary>
        /// Gets or sets the <see cref="CipherData"/> value for an instance of an <see cref="EncryptedType"/> class.
        /// </summary>
        public virtual CipherData CipherData
        {
            get
            {
                if (_cipherData == null)
                    _cipherData = new CipherData();

                return _cipherData;
            }
            set
            {
                _cipherData = value ?? throw new ArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Id"/> attribute of an <see cref="EncryptedType"/> instance in XML encryption.
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="Type"/> attribute of an <see cref="EncryptedType"/> instance in XML encryption.
        /// </summary>
        public virtual string Type { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="MimeType"/> attribute of an <see cref="EncryptedType"/> instance in XML encryption.
        /// </summary>
        /// <remarks>
        /// MimeType attribute is ignored while reading and writing an EncryptedAssertion
        /// </remarks>
        public virtual string MimeType { get; set; }

        /// <summary>
        /// Gets the <see cref="Encoding"/> attribute of an <see cref="EncryptedType"/> instance in XML encryption.
        /// </summary>
        /// <remarks>
        /// Encoding attribute is set to <see cref="XmlSignatureConstants.Base64Encoding"/>
        /// </remarks>
        public virtual string Encoding { get => XmlSignatureConstants.Base64Encoding; }

        /// <summary>
        /// Gets of sets the <see cref="KeyInfo"/> element in XML encryption.
        /// </summary>
        public KeyInfo KeyInfo
        {
            get
            {
                if (_keyInfo == null)
                    _keyInfo = new KeyInfo();
                return _keyInfo;
            }
            set { _keyInfo = value; }
        }

        /// <summary>
        /// Encapsulates the encryption algorithm used for XML encryption.
        /// </summary>
        public EncryptionMethod EncryptionMethod
        {
            get
            {
                if (_encryptionMethod == null)
                    _encryptionMethod = new EncryptionMethod();
                return _encryptionMethod;
            }
            set { _encryptionMethod = value; }
        }

        internal virtual void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (!string.IsNullOrEmpty(Id))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Id, null, Id);

            if (!string.IsNullOrEmpty(Type))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Type, null, Type);

            if (!string.IsNullOrEmpty(MimeType))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.MimeType, null, MimeType);

            if (!string.IsNullOrEmpty(Encoding))
                writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Encoding, null, Encoding);

            EncryptionMethod.WriteXml(writer);
            KeyInfo.WriteXml(writer);
            CipherData.WriteXml(writer);
        }

        internal virtual void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            Id = reader.GetAttribute(XmlEncryptionConstants.Attributes.Id, null);
            Type = reader.GetAttribute(XmlEncryptionConstants.Attributes.Type, null);
            MimeType = reader.GetAttribute(XmlEncryptionConstants.Attributes.MimeType, null);

            reader.ReadStartElement();

            // <EncryptedMethod>? 0 - 1
            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptionMethod, XmlEncryptionConstants.Namespace))
            {
                EncryptionMethod.ReadXml(reader);
            }

            // <KeyInfo>? 0 - 1
            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
            { 
                KeyInfo.ReadXml(reader);
            }

            // <CipherData> 1
            CipherData.ReadXml(reader);

            // <EncryptionProperties>? 0 - 1
            // Skip - not supported
            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptionProperties, XmlEncryptionConstants.Namespace))
            {
                LogInformation(LogMessages.IDX30301, XmlEncryptionConstants.Elements.EncryptionProperties);
                reader.Skip();
            }          
        }
    }
}
