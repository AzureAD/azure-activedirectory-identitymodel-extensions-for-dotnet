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
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using HexBinary = System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary;

namespace Microsoft.IdentityModel.Xml
{
    public class TokenStreamingReader : DelegatingXmlDictionaryReader
    {
        private MemoryStream _contentStream;
        private TextReader _contentReader;
        private int _depth;
        private bool _disposed;
        private bool _recordDone;
        private XmlTokenStream _xmlTokens;

        public TokenStreamingReader(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement())
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX21102));

            InnerReader = reader;
            _xmlTokens = new XmlTokenStream(32);
            Record();
        }

        public XmlTokenStream XmlTokens
        {
            get { return _xmlTokens; }
        }

        public override void Close()
        {
            OnEndOfContent();
            base.InnerReader.Close();
        }

        public override void MoveToAttribute(int index)
        {
            OnEndOfContent();
            base.InnerReader.MoveToAttribute(index);
        }

        public override bool MoveToAttribute(string name)
        {
            OnEndOfContent();
            return base.InnerReader.MoveToAttribute(name);
        }

        public override bool MoveToAttribute(string name, string ns)
        {
            OnEndOfContent();
            return base.InnerReader.MoveToAttribute(name, ns);
        }

        public override bool MoveToElement()
        {
            OnEndOfContent();
            return base.MoveToElement();
        }

        public override bool MoveToFirstAttribute()
        {
            OnEndOfContent();
            return base.MoveToFirstAttribute();
        }

        public override bool MoveToNextAttribute()
        {
            OnEndOfContent();
            return base.MoveToNextAttribute();
        }

        void OnEndOfContent()
        {
            if (_contentReader != null)
            {
                _contentReader.Close();
                _contentReader = null;
            }

            if (_contentStream != null)
            {
                _contentStream.Close();
                _contentStream = null;
            }
        }

        public override bool Read()
        {
            OnEndOfContent();
            if (!base.Read())
            {
                return false;
            }

            if (!_recordDone)
            {
                Record();
            }

            return true;
        }

        int ReadBinaryContent(byte[] buffer, int offset, int count, bool isBase64)
        {
            // TODO - check for bounds
            //CryptoHelper.ValidateBufferBounds(buffer, offset, count);

            //
            // Concatentate text nodes to get entire element value before attempting to convert
            // XmlDictionaryReader.CreateDictionaryReader( XmlReader ) creates a reader that returns base64 in a single text node
            // XmlDictionaryReader.CreateTextReader( Stream ) creates a reader that produces multiple text and whitespace nodes
            // Attribute nodes consist of only a single value
            //
            if (_contentStream == null)
            {
                string encodedValue;
                if (NodeType == XmlNodeType.Attribute)
                {
                    encodedValue = Value;
                }
                else
                {
                    StringBuilder fullText = new StringBuilder(1000);
                    while (NodeType != XmlNodeType.Element && NodeType != XmlNodeType.EndElement)
                    {
                        switch (NodeType)
                        {
                            // concatenate text nodes
                            case XmlNodeType.Text:
                                fullText.Append(Value);
                                break;

                            // skip whitespace
                            case XmlNodeType.Whitespace:
                                break;
                        }

                        Read();
                    }

                    encodedValue = fullText.ToString();
                }

                byte[] value = isBase64 ? Convert.FromBase64String(encodedValue) : HexBinary.Parse(encodedValue).Value;
                _contentStream = new MemoryStream(value);
            }

            int read = _contentStream.Read(buffer, offset, count);
            if (read == 0)
            {
                _contentStream.Close();
                _contentStream = null;
            }

            return read;
        }

        public override int ReadContentAsBase64(byte[] buffer, int offset, int count)
        {
            return ReadBinaryContent(buffer, offset, count, true);
        }

        public override int ReadContentAsBinHex(byte[] buffer, int offset, int count)
        {
            return ReadBinaryContent(buffer, offset, count, false);
        }

        public override int ReadValueChunk(char[] chars, int offset, int count)
        {
            if (_contentReader == null)
                _contentReader = new StringReader(Value);

            return _contentReader.Read(chars, offset, count);
        }

        void Record()
        {
            switch (NodeType)
            {
                case XmlNodeType.Element:
                    {
                        bool isEmpty = base.InnerReader.IsEmptyElement;
                        _xmlTokens.AddElement(base.InnerReader.Prefix, base.InnerReader.LocalName, base.InnerReader.NamespaceURI, isEmpty);
                        if (base.InnerReader.MoveToFirstAttribute())
                        {
                            do
                            {
                                _xmlTokens.AddAttribute(base.InnerReader.Prefix, base.InnerReader.LocalName, base.InnerReader.NamespaceURI, base.InnerReader.Value);
                            }
                            while (base.InnerReader.MoveToNextAttribute());
                            base.InnerReader.MoveToElement();
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
                        _xmlTokens.Add(NodeType, Value);
                        break;
                    }
                case XmlNodeType.EndElement:
                    {
                        _xmlTokens.Add(NodeType, Value);
                        if (--_depth == 0)
                        {
                            _recordDone = true;
                        }
                        break;
                    }
                case XmlNodeType.DocumentType:
                case XmlNodeType.XmlDeclaration:
                    {
                        break;
                    }
                default:
                    {
                        throw LogHelper.LogExceptionMessage(new XmlException("UnsupportedNodeTypeInReader, base.InnerReader.NodeType, base.InnerReader.Name"));
                    }

            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_disposed)
                return;

            if (disposing)
            {
                //
                // Free all of our managed resources
                //
                if (_contentReader != null)
                {
                    _contentReader.Dispose();
                    _contentReader = null;
                }

                if (_contentStream != null)
                {
                    _contentStream.Dispose();
                    _contentStream = null;
                }
            }

            _disposed = true;
        }
    }
}
