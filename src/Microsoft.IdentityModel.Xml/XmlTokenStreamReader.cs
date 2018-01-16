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
    /// An XmlReader that captures xml as a XmlTokenStream
    /// </summary>
    public class XmlTokenStreamReader : DelegatingXmlDictionaryReader
    {
        private int _depth;
        private bool _recordDone;

        /// <summary>
        /// Initializes a new instance of <see cref="XmlTokenStreamReader"/> for creating a <see cref="XmlTokenStream"/>.
        /// </summary>
        /// <param name="reader">an <see cref="XmlDictionaryReader"/> to capture the <see cref="XmlTokenStream"/>.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> if null.</exception>
        /// <exception cref="ArgumentException">if <paramref name="reader"/>.IsStartElement() is false.</exception>
        public XmlTokenStreamReader(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement())
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(LogMessages.IDX14102, reader.NodeType)));

            TokenStream = new XmlTokenStream();
            InnerReader = reader;
            Record();
        }

        /// <summary>
        /// Gets the <see cref="XmlTokenStream"/>
        /// </summary>
        public XmlTokenStream TokenStream
        {
            get;
        }

        /// <summary>
        /// Delegates to InnerReader, then calls Record()
        /// </summary>
        public override bool Read()
        {
            if (!InnerReader.Read())
                return false;

            if (!_recordDone)
                Record();

            return true;
        }

        private void Record()
        {
            switch (InnerReader.NodeType)
            {
                case XmlNodeType.Element:
                {
                    bool isEmpty = InnerReader.IsEmptyElement;
                    TokenStream.AddElement(InnerReader.Prefix, InnerReader.LocalName, InnerReader.NamespaceURI, isEmpty);
                    if (InnerReader.MoveToFirstAttribute())
                    {
                        do
                        {
                            TokenStream.AddAttribute(InnerReader.Prefix, InnerReader.LocalName, InnerReader.NamespaceURI, InnerReader.Value);
                        }
                        while (InnerReader.MoveToNextAttribute());
                            InnerReader.MoveToElement();
                    }

                    if (!isEmpty)
                    {
                        _depth++;
                    }
                    else if (_depth == 0)
                    {
                        _recordDone = true;
                    }

                    break;
                }
                case XmlNodeType.CDATA:
                case XmlNodeType.Comment:
                case XmlNodeType.Text:
                case XmlNodeType.EntityReference:
                case XmlNodeType.EndEntity:
                case XmlNodeType.SignificantWhitespace:
                case XmlNodeType.Whitespace:
                {
                    TokenStream.Add(InnerReader.NodeType, InnerReader.Value);
                    break;
                }
                case XmlNodeType.EndElement:
                {
                    TokenStream.Add(InnerReader.NodeType, InnerReader.Value);
                    if (--_depth == 0)
                        _recordDone = true;

                    break;
                }
                case XmlNodeType.DocumentType:
                case XmlNodeType.XmlDeclaration:
                { 
                    break;
                }
                default:
                {
                    throw LogExceptionMessage(new XmlException(FormatInvariant(LogMessages.IDX14023, InnerReader.NodeType)));
                }
            }
        }
    }
}
