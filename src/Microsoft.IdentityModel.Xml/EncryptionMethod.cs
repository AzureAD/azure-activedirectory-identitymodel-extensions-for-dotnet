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

using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the <see cref="EncryptionMethod"/> element in XML encryption that describes the encryption algorithm applied to the cipher data. This class cannot be inherited.
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core/#sec-EncryptionMethod </remarks>
    public class EncryptionMethod
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionMethod"/> class.
        /// </summary>
        public EncryptionMethod()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionMethod"/> class specifying an algorithm Uniform Resource Identifier(URI).
        /// </summary>
        /// <param name="algorithm"></param>
        public EncryptionMethod(string algorithm)
        {
            KeyAlgorithm = algorithm;
        }

        /// <summary>
        /// Gets or sets a Uniform Resource Identifier (URI) that describes the algorithm to use for XML encryption.
        /// </summary>
        public string KeyAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the digest method Uniform Resource Identifier (URI)
        /// </summary>
        public string DigestMethod { get; set; }

        internal void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            // nothing to write - return
            if (string.IsNullOrEmpty(KeyAlgorithm))
                return;

            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.EncryptionMethod, XmlEncryptionConstants.Namespace);
            writer.WriteAttributeString(XmlEncryptionConstants.Attributes.Algorithm, null, KeyAlgorithm);

            if (!string.IsNullOrEmpty(DigestMethod))
            {
                writer.WriteStartElement(XmlSignatureConstants.PreferredPrefix, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, DigestMethod);
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        internal void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptionMethod, XmlEncryptionConstants.Namespace))
            {
                KeyAlgorithm = reader.GetAttribute(XmlEncryptionConstants.Attributes.Algorithm, null);

                if (reader.IsEmptyElement)
                {
                    reader.Read();
                    return;
                }

                reader.ReadStartElement(XmlEncryptionConstants.Elements.EncryptionMethod, XmlEncryptionConstants.Namespace);

                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace))
                    {
                        DigestMethod = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                    }
                    else
                    {
                        LogInformation(LogMessages.IDX30302, reader.LocalName, XmlEncryptionConstants.Elements.EncryptionMethod);
                    }

                    reader.Skip();
                }

                reader.ReadEndElement();
            }
        }
    }
}
