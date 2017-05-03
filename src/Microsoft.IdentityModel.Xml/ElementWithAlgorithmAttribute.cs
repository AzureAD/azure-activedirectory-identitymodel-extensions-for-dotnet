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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    internal struct ElementWithAlgorithmAttribute
    {
        private readonly string _elementName;

        public ElementWithAlgorithmAttribute(string elementName)
        {
            if (string.IsNullOrEmpty(elementName))
                throw LogHelper.LogArgumentNullException(nameof(elementName));

            _elementName = elementName;
            Algorithm = null;
            Prefix = XmlSignatureConstants.Prefix;
        }

        public string Algorithm { get; set; }

        public string Prefix { get; set; }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, _elementName, XmlSignatureConstants.Namespace);

            reader.MoveToStartElement(_elementName, XmlSignatureConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            Prefix = reader.Prefix;
            Algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            if (Algorithm == null)
                throw XmlUtil.OnRequiredAttributeMissing(_elementName, XmlSignatureConstants.Attributes.Algorithm);

            reader.Read();
            reader.MoveToContent();

            if (!isEmptyElement)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(Prefix, _elementName, XmlSignatureConstants.Namespace);
            writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            writer.WriteString(Algorithm);
            writer.WriteEndAttribute();
            writer.WriteEndElement();
        }
    }
}