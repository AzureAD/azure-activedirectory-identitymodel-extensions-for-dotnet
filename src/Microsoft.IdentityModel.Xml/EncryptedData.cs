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
    /// Represents the <see cref="EncryptedData"/> element in XML encryption. This class cannot be inherited.
    /// </summary>
    /// <remarks> http://www.w3.org/TR/xmlenc-core/#sec-EncryptedData </remarks>
    public sealed class EncryptedData : EncryptedType
    {
        /// <summary>
        /// Initializes an instance of <see cref="EncryptedData"/>.
        /// </summary>
        public EncryptedData()
        {
            Type = XmlEncryptionConstants.EncryptedDataTypes.Element;
        }

        internal override void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.EncryptedData, XmlEncryptionConstants.Namespace);
            base.WriteXml(writer);
            writer.WriteEndElement();
        }

        internal override void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptedData, XmlEncryptionConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlEncryptionConstants.Namespace, XmlEncryptionConstants.Elements.EncryptedData, reader.NamespaceURI, reader.LocalName);

            base.ReadXml(reader);

            reader.ReadEndElement();
        }
    }
}
