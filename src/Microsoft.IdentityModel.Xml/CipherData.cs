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
    /// Represents the <see cref="CipherData"/> element in XML encryption. This class cannot be inherited.
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core/#sec-CipherData </remarks>
    public sealed class CipherData
    {
        private byte[] _cipherValue = null;

        /// <summary>
        /// Initializes an instance of <see cref="CipherData"/>.
        /// </summary>
        public CipherData()
        { }

        /// <summary>
        /// Initializes an instance of <see cref="CipherData"/>.
        /// </summary>
        /// <param name="cipherValue"></param>
        public CipherData(byte[] cipherValue)
        {
            CipherValue = cipherValue;
        }

        /// <summary>
        /// Gets or sets the <see cref="CipherValue"/> element.
        /// </summary>
        public byte[] CipherValue
        {
            get { return _cipherValue; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                _cipherValue = (byte[])value.Clone();
            }
        }

        internal void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.CipherData, XmlEncryptionConstants.Namespace);
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.CipherValue, XmlEncryptionConstants.Namespace);

            writer.WriteBase64(_cipherValue, 0, _cipherValue.Length);

            writer.WriteEndElement(); // CipherValue
            writer.WriteEndElement(); // CipherData
        }

        internal void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(XmlEncryptionConstants.Elements.CipherData, XmlEncryptionConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlEncryptionConstants.Namespace, XmlEncryptionConstants.Elements.CipherData, reader.NamespaceURI, reader.LocalName);

            reader.ReadStartElement(XmlEncryptionConstants.Elements.CipherData, XmlEncryptionConstants.Namespace);

            if (!reader.IsStartElement(XmlEncryptionConstants.Elements.CipherValue, XmlEncryptionConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlEncryptionConstants.Namespace, XmlEncryptionConstants.Elements.CipherValue, reader.NamespaceURI, reader.LocalName);

            reader.ReadStartElement(XmlEncryptionConstants.Elements.CipherValue, XmlEncryptionConstants.Namespace);

            _cipherValue = reader.ReadContentAsBase64();

            // <CipherValue>
            reader.ReadEndElement();

            // <CipherData>
            reader.ReadEndElement();
        }
    }
}
