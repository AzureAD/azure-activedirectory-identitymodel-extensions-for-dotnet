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
    /// Class wraps a given reader and delegates all XmlDictionaryReader calls 
    /// to the inner wrapped reader.
    /// </summary>
    public class DelegatingXmlDictionaryReader : XmlDictionaryReader, IXmlLineInfo
    {
        private XmlDictionaryReader _innerReader;

        /// <summary>
        /// Initializes the Inner reader that this instance wraps.
        /// </summary>
        /// <param name="innerReader">XmlDictionaryReader to wrap.</param>
        protected void SetCanonicalizingReader(XmlDictionaryReader innerReader)
        {
            if (innerReader == null)
                throw LogHelper.LogArgumentNullException(nameof(innerReader));

            _innerReader = innerReader;
        }

        /// <summary>
        /// Gets the wrapped inner reader.
        /// </summary>
        protected XmlDictionaryReader InnerReader
        {
            get { return _innerReader; }
        }

        /// <summary>
        /// Gets the value of the attribute with the specified index.
        /// </summary>
        /// <param name="i">index of the attribute.</param>
        /// <returns>Attribute value at the specified index.</returns>
        public override string this[int i]
        {
            get { return _innerReader[i]; }
        }

        /// <summary>
        /// Gets the value of the attribute with the specified System.Xml.XmlReader.Name.
        /// </summary>
        /// <param name="name">The qualified name of the attribute.</param>
        /// <returns>The value of the specified attribute. If the attribute is not found, 
        /// null is returned.</returns>
        public override string this[string name]
        {
            get { return _innerReader[name]; }
        }

        /// <summary>
        /// Gets the value of the attribute with the specified System.Xml.XmlReader.LocalName and 
        /// System.Xml.XmlReader.NamespaceURI from the wrapped reader.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="ns">The namespace URI of the attribute.</param>
        /// <returns>The value of the specified attribute. If the attribute is not found, 
        /// null is returned.</returns>
        public override string this[string name, string ns]
        {
            get { return _innerReader[name, ns]; }
        }

        /// <summary>
        /// Gets the number of Attributes at the current reader position.
        /// </summary>
        public override int AttributeCount
        {
            get { return _innerReader.AttributeCount; }
        }

        /// <summary>
        /// Gets the base Uri of the current node.
        /// </summary>
        public override string BaseURI
        {
            get { return _innerReader.BaseURI; }
        }

        public override bool CanReadBinaryContent
        {
            get { return _innerReader.CanReadBinaryContent; }
        }

        public override bool CanReadValueChunk
        {
            get { return _innerReader.CanReadValueChunk; }
        }

        /// <summary>
        /// Gets the Depth of the current node.
        /// </summary>
        public override int Depth
        {
            get { return _innerReader.Depth; }
        }

        /// <summary>
        /// Gets a value indicating if reader is positioned at the end of the stream.
        /// </summary>
        public override bool EOF
        {
            get { return _innerReader.EOF; }
        }

        /// <summary>
        /// Gets a value indicating if the current node can have a 
        /// System.Xml.XmlReader.Value.
        /// </summary>
        public override bool HasValue
        {
            get { return _innerReader.HasValue; }
        }

        /// <summary>
        /// Gets a value indicating if the current node is an attribute that
        /// was generated from the default value defined in the DTD or Schema.
        /// </summary>
        public override bool IsDefault
        {
            get { return _innerReader.IsDefault; }
        }

        /// <summary>
        /// Gets a value indicating if the current node.
        /// </summary>
        public override bool IsEmptyElement
        {
            get { return _innerReader.IsEmptyElement; }
        }

        public int LineNumber
        {
            get
            {
                var lineInfo = _innerReader as IXmlLineInfo;
                if (lineInfo == null)
                    return 1;

                return lineInfo.LineNumber;
            }
        }

        public int LinePosition
        {
            get
            {
                var lineInfo = _innerReader as IXmlLineInfo;
                if (lineInfo == null)
                    return 1;

                return lineInfo.LinePosition;
            }
        }

        /// <summary>
        /// Gets the local name of the current node.
        /// </summary>
        public override string LocalName
        {
            get { return _innerReader.LocalName; }
        }

        /// <summary>
        /// Gets the qualified name of the current node.
        /// </summary>
        public override string Name
        {
            get { return _innerReader.Name; }
        }

        /// <summary>
        /// Gets the namespace URI of the current node.
        /// </summary>
        public override string NamespaceURI
        {
            get { return _innerReader.NamespaceURI; }
        }

        /// <summary>
        /// Gets the System.Xml.XmlNameTable associated with this instance.
        /// </summary>
        public override XmlNameTable NameTable
        {
            get { return _innerReader.NameTable; }
        }

        /// <summary>
        /// Gets the type of the current node.
        /// </summary>
        public override XmlNodeType NodeType
        {
            get { return _innerReader.NodeType; }
        }

        /// <summary>
        /// Gets the prefix of the current node.
        /// </summary>
        public override string Prefix
        {
            get { return _innerReader.Prefix; }
        }

        /// <summary>
        /// Gets the quotation mark character used to enclose the attribute node. (" or ')
        /// </summary>
        public override char QuoteChar
        {
            get { return _innerReader.QuoteChar; }
        }

        /// <summary>
        /// Gets the System.Xml.ReadState of the reader. 
        /// </summary>
        public override ReadState ReadState
        {
            get { return _innerReader.ReadState; }
        }

        /// <summary>
        /// Gets the text value of the current node.
        /// </summary>
        public override string Value
        {
            get { return _innerReader.Value; }
        }

        /// <summary>
        /// Gets the Common Language Runtime (CLR) type of the curent node.
        /// </summary>
        public override Type ValueType
        {
            get { return _innerReader.ValueType; }
        }

        /// <summary>
        /// Gets the xml:lang scope.
        /// </summary>
        public override string XmlLang
        {
            get { return _innerReader.XmlLang; }
        }

        /// <summary>
        /// Gets the current xml:space scope. If no xml:space scope exists, this property 
        /// defaults to XmlSpace.None.
        /// </summary>
        public override XmlSpace XmlSpace
        {
            get { return _innerReader.XmlSpace; }
        }

        /// <summary>
        /// Closes the reader and changes the System.Xml.XmlReader.ReadState
        /// to Closed.
        /// </summary>
        public override void Close()
        {
            _innerReader.Close();
        }

        /// <summary>
        /// Gets the value of the attribute at the given index.
        /// </summary>
        /// <param name="i">The index of the attribute. The index is 0 based index.</param>
        /// <returns>The value of the attribute at the specified index.</returns>
        /// <remarks>The method does not move the reader position.</remarks>
        public override string GetAttribute(int i)
        {
            return _innerReader.GetAttribute(i);
        }

        /// <summary>
        /// Gets the value of the attribute with the given name.
        /// </summary>
        /// <param name="name">The qualified name of the attribute.</param>
        /// <returns>The value of the attribute. If the attribute is not found null
        /// is returned.</returns>
        /// <remarks>The method does not move the reader position.</remarks>
        public override string GetAttribute(string name)
        {
            return _innerReader.GetAttribute(name);
        }

        /// <summary>
        /// Gets the value of the attribute with the given name and namespace Uri.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="ns">The namespace of the attribute.</param>
        /// <returns>The value of the attribute. If the attribute is not found
        /// null is returned.</returns>
        /// <remarks>The method does not move the reader.</remarks>
        public override string GetAttribute(string name, string ns)
        {
            return _innerReader.GetAttribute(name, ns);
        }

        public bool HasLineInfo()
        {
            var lineInfo = _innerReader as IXmlLineInfo;

            if (lineInfo == null)
                return false;

            return lineInfo.HasLineInfo();
        }

        public override bool IsStartElement(string name)
        {
            return _innerReader.IsStartElement(name);
        }

        public override bool IsStartElement(string name, string ns)
        {
            return _innerReader.IsStartElement(name, ns);
        }

        /// <summary>
        /// Resolves a namespace prefix in the current element scope.
        /// </summary>
        /// <param name="prefix">Prefix whose namespace Uri to be resolved.</param>
        /// <returns>The namespace Uri to which the prefix matches or null if no matching
        /// prefix is found.</returns>
        public override string LookupNamespace(string prefix)
        {
            return _innerReader.LookupNamespace(prefix);
        }

        /// <summary>
        /// Moves to the attribute with the specified index.
        /// </summary>
        /// <param name="index">The index of the attribute.</param>
        public override void MoveToAttribute(int index)
        {
            _innerReader.MoveToAttribute(index);
        }

        /// <summary>
        /// Moves to the attribute with the given local name.
        /// </summary>
        /// <param name="name">The qualified name of the attribute.</param>
        /// <returns>true if the attribute is found; otherwise, false.</returns>
        public override bool MoveToAttribute(string name)
        {
            return _innerReader.MoveToAttribute(name);
        }

        /// <summary>
        /// Moves to the attribute with the specified System.Xml.XmlReader.LocalName and 
        /// System.Xml.XmlReader.NamespaceURI.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="ns">The namespace URI of the attribute.</param>
        /// <returns>true if the attribute is found; otherwise, false.</returns>
        public override bool MoveToAttribute(string name, string ns)
        {
            return _innerReader.MoveToAttribute(name, ns);
        }

        /// <summary>
        /// Moves to a node of type Element.
        /// </summary>
        /// <returns>true if the reader is positioned on an element else false</returns>
        public override bool MoveToElement()
        {
            return _innerReader.MoveToElement();
        }

        /// <summary>
        /// Moves to the first attribute.
        /// </summary>
        /// <returns>Returns true if the reader is positioned at a attribute else false.</returns>
        /// <remarks>When returning false the reader position will not be changed.</remarks>
        public override bool MoveToFirstAttribute()
        {
            return _innerReader.MoveToFirstAttribute();
        }

        /// <summary>
        /// Moves the reader to the next attribute.
        /// </summary>
        /// <returns>Returns true if the reader is positioned at an attribute else false.</returns>
        /// <remarks>When returning false the reader position will not be changed.</remarks>
        public override bool MoveToNextAttribute()
        {
            return _innerReader.MoveToNextAttribute();
        }

        /// <summary>
        /// Reads the next node from the stream.
        /// </summary>
        /// <returns>true if the next node was read successfully.</returns>
        public override bool Read()
        {
            return _innerReader.Read();
        }

        /// <summary>
        /// Parses the attribute value into one or more Text, EntityReference, or EndEntity nodes.
        /// </summary>
        /// <returns>true if there are nodes to return.false if the reader is not positioned on
        /// an attribute node when the initial call is made or if all the attribute values
        /// have been read.</returns>
        public override bool ReadAttributeValue()
        {
            return _innerReader.ReadAttributeValue();
        }

        public override object ReadContentAs(Type valueType, IXmlNamespaceResolver namespaceResolver)
        {
            return _innerReader.ReadContentAs(valueType, namespaceResolver);
        }

        /// <summary>
        /// Reads the content and returns the Base64 decoded binary bytes.
        /// </summary>
        /// <param name="buffer">The buffer into which to copy the resulting text. This value cannot be null.</param>
        /// <param name="index">The offset into the buffer where to start copying the result.</param>
        /// <param name="count">The maximum number of bytes to copy into the buffer.</param>
        /// <returns>The number of bytes written to the buffer.</returns>
        public override int ReadContentAsBase64(byte[] buffer, int index, int count)
        {
            return _innerReader.ReadContentAsBase64(buffer, index, count);
        }

        /// <summary>
        /// Reads the content and returns the BinHex decoded binary bytes.
        /// </summary>
        /// <param name="buffer">The buffer into which to copy the resulting text. This value cannot be null.</param>
        /// <param name="index">The offset into the buffer where to start copying the result.</param>
        /// <param name="count">The maximum number of bytes to copy into the buffer.</param>
        /// <returns>The number of bytes written to the buffer.</returns>
        public override int ReadContentAsBinHex(byte[] buffer, int index, int count)
        {
            return _innerReader.ReadContentAsBinHex(buffer, index, count);
        }

        public override bool ReadContentAsBoolean()
        {
            return _innerReader.ReadContentAsBoolean();
        }

        public override DateTime ReadContentAsDateTime()
        {
            return _innerReader.ReadContentAsDateTime();
        }

        public override decimal ReadContentAsDecimal()
        {
            return (decimal)_innerReader.ReadContentAs(typeof(decimal), null);
        }

        public override double ReadContentAsDouble()
        {
            return _innerReader.ReadContentAsDouble();
        }

        public override int ReadContentAsInt()
        {
            return _innerReader.ReadContentAsInt();
        }

        public override long ReadContentAsLong()
        {
            return _innerReader.ReadContentAsLong();
        }

        public override float ReadContentAsFloat()
        {
            return _innerReader.ReadContentAsFloat();
        }

        public override string ReadContentAsString()
        {
            return _innerReader.ReadContentAsString();
        }

        /// <summary>
        /// Reads the content and returns the contained string.
        /// </summary>
        public override UniqueId ReadContentAsUniqueId()
        {
            return _innerReader.ReadContentAsUniqueId();
        }

        public override int ReadElementContentAsBase64(byte[] buffer, int offset, int count)
        {
            return _innerReader.ReadElementContentAsBase64(buffer, offset, count);
        }

        public override int ReadElementContentAsBinHex(byte[] buffer, int offset, int count)
        {
            return _innerReader.ReadElementContentAsBinHex(buffer, offset, count);
        }

        public override string ReadElementString(string name)
        {
            return _innerReader.ReadElementString(name);
        }

        public override string ReadElementString(string name, string ns)
        {
            return _innerReader.ReadElementString(name, ns);
        }

        public override string ReadInnerXml()
        {
            return _innerReader.ReadInnerXml();
        }

        public override string ReadOuterXml()
        {
            return _innerReader.ReadOuterXml();
        }
        public override void ReadEndElement()
        {
            _innerReader.ReadEndElement();
        }

        public override void ReadStartElement(string name)
        {
            _innerReader.ReadStartElement(name);
        }

        public override void ReadStartElement(string name, string ns)
        {
            _innerReader.ReadStartElement(name, ns);
        }

        public override string ReadString()
        {
            return _innerReader.ReadString();
        }

        public override void ResolveEntity()
        {
            _innerReader.ResolveEntity();
        }

        /// <summary>
        /// Reads large streams of text embedded in an XML document.
        /// </summary>
        /// <param name="buffer">The array of characters that serves as the buffer to which the text contents
        /// are written. This value cannot be null.</param>
        /// <param name="index">The offset within the buffer where the System.Xml.XmlReader can start to
        /// copy the results.</param>
        /// <param name="count">The maximum number of characters to copy into the buffer. The actual number
        /// of characters copied is returned from this method.</param>
        /// <returns>The number of characters read into the buffer. The value zero is returned
        /// when there is no more text content.</returns>
        public override int ReadValueChunk(char[] buffer, int index, int count)
        {
            return _innerReader.ReadValueChunk(buffer, index, count);
        }
    }
}
