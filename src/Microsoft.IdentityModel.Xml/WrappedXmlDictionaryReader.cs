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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// This class wraps a given _reader and delegates all calls to it. 
    /// XmlDictionaryReader class does not provide a way to set the _reader
    /// Quotas on the XmlDictionaryReader.CreateDictionaryReader(XmlReader)
    /// API. This class overrides XmlDictionaryReader.Quotas property and 
    /// hence custom quotas can be specified.
    /// </summary>
    internal class WrappedXmlDictionaryReader : XmlDictionaryReader, IXmlLineInfo
    {
        private XmlReader _reader;
        private XmlDictionaryReaderQuotas _xmlDictionaryReaderQuotas;

        public WrappedXmlDictionaryReader(
            XmlReader reader,
            XmlDictionaryReaderQuotas xmlDictionaryReaderQuotas)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (xmlDictionaryReaderQuotas == null)
                throw LogHelper.LogArgumentNullException(nameof(xmlDictionaryReaderQuotas));

            _reader = reader;
            _xmlDictionaryReaderQuotas = xmlDictionaryReaderQuotas;
        }

        public override int AttributeCount
        {
            get
            {
                return _reader.AttributeCount;
            }
        }

        public override string BaseURI
        {
            get
            {
                return _reader.BaseURI;
            }
        }

        public override bool CanReadBinaryContent
        {
            get { return _reader.CanReadBinaryContent; }
        }

        public override bool CanReadValueChunk
        {
            get { return _reader.CanReadValueChunk; }
        }

        public override int Depth
        {
            get
            {
                return _reader.Depth;
            }
        }

        public override bool EOF
        {
            get
            {
                return _reader.EOF;
            }
        }

        public override bool HasValue
        {
            get
            {
                return _reader.HasValue;
            }
        }

        public override bool IsDefault
        {
            get
            {
                return _reader.IsDefault;
            }
        }

        public override bool IsEmptyElement
        {
            get
            {
                return _reader.IsEmptyElement;
            }
        }

        public override string LocalName
        {
            get
            {
                return _reader.LocalName;
            }
        }

        public override string Name
        {
            get
            {
                return _reader.Name;
            }
        }

        public override string NamespaceURI
        {
            get
            {
                return _reader.NamespaceURI;
            }
        }

        public override XmlNameTable NameTable
        {
            get
            {
                return _reader.NameTable;
            }
        }

        public override XmlNodeType NodeType
        {
            get
            {
                return _reader.NodeType;
            }
        }

        public override string Prefix
        {
            get
            {
                return _reader.Prefix;
            }
        }

        public override char QuoteChar
        {
            get
            {
                return _reader.QuoteChar;
            }
        }

        public override ReadState ReadState
        {
            get
            {
                return _reader.ReadState;
            }
        }

        public override string Value
        {
            get
            {
                return _reader.Value;
            }
        }

        public override string XmlLang
        {
            get
            {
                return _reader.XmlLang;
            }
        }

        public override XmlSpace XmlSpace
        {
            get
            {
                return _reader.XmlSpace;
            }
        }

        public override Type ValueType
        {
            get
            {
                return _reader.ValueType;
            }
        }

        public int LineNumber
        {
            get
            {
                IXmlLineInfo lineInfo = _reader as IXmlLineInfo;

                if (lineInfo == null)
                {
                    return 1;
                }

                return lineInfo.LineNumber;
            }
        }

        public int LinePosition
        {
            get
            {
                IXmlLineInfo lineInfo = _reader as IXmlLineInfo;

                if (lineInfo == null)
                {
                    return 1;
                }

                return lineInfo.LinePosition;
            }
        }

        public override XmlDictionaryReaderQuotas Quotas
        {
            get
            {
                return _xmlDictionaryReaderQuotas;
            }
        }

        public override string this[int index]
        {
            get
            {
                return _reader[index];
            }
        }

        public override string this[string name]
        {
            get
            {
                return _reader[name];
            }
        }

        public override string this[string name, string namespaceUri]
        {
            get
            {
                return _reader[name, namespaceUri];
            }
        }

        public override void Close()
        {
            _reader.Close();
        }

        public override string GetAttribute(int index)
        {
            return _reader.GetAttribute(index);
        }

        public override string GetAttribute(string name)
        {
            return _reader.GetAttribute(name);
        }

        public override string GetAttribute(string name, string namespaceUri)
        {
            return _reader.GetAttribute(name, namespaceUri);
        }

        public override bool IsStartElement(string name)
        {
            return _reader.IsStartElement(name);
        }

        public override bool IsStartElement(string localName, string namespaceUri)
        {
            return _reader.IsStartElement(localName, namespaceUri);
        }

        public override string LookupNamespace(string namespaceUri)
        {
            return _reader.LookupNamespace(namespaceUri);
        }

        public override void MoveToAttribute(int index)
        {
            _reader.MoveToAttribute(index);
        }

        public override bool MoveToAttribute(string name)
        {
            return _reader.MoveToAttribute(name);
        }

        public override bool MoveToAttribute(string name, string namespaceUri)
        {
            return _reader.MoveToAttribute(name, namespaceUri);
        }

        public override bool MoveToElement()
        {
            return _reader.MoveToElement();
        }

        public override bool MoveToFirstAttribute()
        {
            return _reader.MoveToFirstAttribute();
        }

        public override bool MoveToNextAttribute()
        {
            return _reader.MoveToNextAttribute();
        }

        public override bool Read()
        {
            return _reader.Read();
        }

        public override bool ReadAttributeValue()
        {
            return _reader.ReadAttributeValue();
        }

        public override string ReadElementString(string name)
        {
            return _reader.ReadElementString(name);
        }

        public override string ReadElementString(string localName, string namespaceUri)
        {
            return _reader.ReadElementString(localName, namespaceUri);
        }

        public override string ReadInnerXml()
        {
            return _reader.ReadInnerXml();
        }

        public override string ReadOuterXml()
        {
            return _reader.ReadOuterXml();
        }

        public override void ReadStartElement(string name)
        {
            _reader.ReadStartElement(name);
        }

        public override void ReadStartElement(string localName, string namespaceUri)
        {
            _reader.ReadStartElement(localName, namespaceUri);
        }

        public override void ReadEndElement()
        {
            _reader.ReadEndElement();
        }

        public override string ReadString()
        {
            return _reader.ReadString();
        }

        public override void ResolveEntity()
        {
            _reader.ResolveEntity();
        }

        public override int ReadElementContentAsBase64(byte[] buffer, int offset, int count)
        {
            return _reader.ReadElementContentAsBase64(buffer, offset, count);
        }

        public override int ReadContentAsBase64(byte[] buffer, int offset, int count)
        {
            return _reader.ReadContentAsBase64(buffer, offset, count);
        }

        public override int ReadElementContentAsBinHex(byte[] buffer, int offset, int count)
        {
            return _reader.ReadElementContentAsBinHex(buffer, offset, count);
        }

        public override int ReadContentAsBinHex(byte[] buffer, int offset, int count)
        {
            return _reader.ReadContentAsBinHex(buffer, offset, count);
        }

        public override int ReadValueChunk(char[] chars, int offset, int count)
        {
            return _reader.ReadValueChunk(chars, offset, count);
        }

        public override bool ReadContentAsBoolean()
        {
            return _reader.ReadContentAsBoolean();
        }

        public override DateTime ReadContentAsDateTime()
        {
            return _reader.ReadContentAsDateTime();
        }

        public override decimal ReadContentAsDecimal()
        {
            return (decimal)_reader.ReadContentAs(typeof(decimal), null);
        }

        public override double ReadContentAsDouble()
        {
            return _reader.ReadContentAsDouble();
        }

        public override int ReadContentAsInt()
        {
            return _reader.ReadContentAsInt();
        }

        public override long ReadContentAsLong()
        {
            return _reader.ReadContentAsLong();
        }

        public override float ReadContentAsFloat()
        {
            return _reader.ReadContentAsFloat();
        }

        public override string ReadContentAsString()
        {
            return _reader.ReadContentAsString();
        }

        public override object ReadContentAs(Type valueType, IXmlNamespaceResolver namespaceResolver)
        {
            return _reader.ReadContentAs(valueType, namespaceResolver);
        }

        public bool HasLineInfo()
        {
            IXmlLineInfo lineInfo = _reader as IXmlLineInfo;

            if (lineInfo == null)
            {
                return false;
            }

            return lineInfo.HasLineInfo();
        }
    }
}
