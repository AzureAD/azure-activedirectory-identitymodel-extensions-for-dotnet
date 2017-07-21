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
    /// Class wraps a given reader and delegates all XmlDictionaryReader calls 
    /// to the inner wrapped reader it is used to set up a callback relationship
    /// so that special processing can be performed on 'Read'.
    /// </summary>
    public class DelegatingXmlDictionaryReader : XmlDictionaryReader, IXmlLineInfo
    {
        private XmlDictionaryReader _innerReader;

        /// <summary>
        /// Gets or sets the Inner <see cref="XmlDictionaryReader"/>.
        /// </summary>
        protected XmlDictionaryReader InnerReader
        {
            get => _innerReader;
            set => _innerReader = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the value of the InnerReaders's attribute with the specified index.
        /// </summary>
        /// <param name="i">index of the attribute.</param>
        /// <returns>Attribute value at the specified index.</returns>
        public override string this[int i]
        {
            get => _innerReader[i];
        }

        /// <summary>
        /// Gets the value of the InnerReaders's attribute with the specified Name.
        /// </summary>
        /// <param name="name">The qualified name of the attribute.</param>
        /// <returns>The value of the specified attribute. If the attribute is not found, 
        /// null is returned.</returns>
        public override string this[string name]
        {
            get => _innerReader[name];
        }

        /// <summary>
        /// Gets the value of the InnerReaders's attribute with the specified LocalName and NamespaceURI.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="namespace">The namespace URI of the attribute.</param>
        /// <returns>The value of the specified attribute. If the attribute is not found, 
        /// null is returned.</returns>
        public override string this[string name, string @namespace]
        {
            get => _innerReader[name, @namespace];
        }

        /// <summary>
        /// Gets the number of InnerReaders's attributes at the current reader position.
        /// </summary>
        public override int AttributeCount
        {
            get => _innerReader.AttributeCount;
        }

        /// <summary>
        /// Gets the InnerReaders's base Uri of the current node.
        /// </summary>
        public override string BaseURI
        {
            get => _innerReader.BaseURI;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader can read binary content
        /// </summary>
        public override bool CanReadBinaryContent
        {
            get => _innerReader.CanReadBinaryContent;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader can read value chunk.
        /// </summary>
        public override bool CanReadValueChunk
        {
            get => _innerReader.CanReadValueChunk;
        }

        /// <summary>
        /// Gets the  InnerReaders's current depth.
        /// </summary>
        public override int Depth
        {
            get => _innerReader.Depth;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader is positioned at the end of the stream.
        /// </summary>
        public override bool EOF
        {
            get => _innerReader.EOF;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader current node has a Value.
        /// </summary>
        public override bool HasValue
        {
            get => _innerReader.HasValue;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader's current node is an attribute that
        /// was generated from the default value defined in the DTD or Schema.
        /// </summary>
        public override bool IsDefault
        {
            get => _innerReader.IsDefault;
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader's current node is empty.
        /// </summary>
        public override bool IsEmptyElement
        {
            get => _innerReader.IsEmptyElement;
        }

        /// <summary>
        /// Gets the InnerReader's LineNumber
        /// </summary>
        /// <remarks>If the InnerReader does not support <see cref="IXmlLineInfo"/> 1 is returned.</remarks>
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

        /// <summary>
        /// Gets the InnerReader's LinePosition.
        /// </summary>
        /// <remarks>If the InnerReader does not support <see cref="IXmlLineInfo"/> 1 is returned.</remarks>
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
        /// Gets the InnerReader's LocalName of the current node.
        /// </summary>
        public override string LocalName
        {
            get { return _innerReader.LocalName; }
        }

        /// <summary>
        /// Gets the InnerReader's Name of the current node.
        /// </summary>
        public override string Name
        {
            get => _innerReader.Name;
        }

        /// <summary>
        /// Gets the InnerReader's NamespaceURI of the current node.
        /// </summary>
        public override string NamespaceURI
        {
            get => _innerReader.NamespaceURI;
        }

        /// <summary>
        /// Gets the InnerReader's XmlNameTable at the current node.
        /// </summary>
        public override XmlNameTable NameTable
        {
            get => _innerReader.NameTable;
        }

        /// <summary>
        /// Gets the type of the InnerReader's current node type.
        /// </summary>
        public override XmlNodeType NodeType
        {
            get => _innerReader.NodeType;
        }

        /// <summary>
        /// Gets the prefix of the InnerReader's current node.
        /// </summary>
        public override string Prefix
        {
            get => _innerReader.Prefix;
        }

#if DESKTOPNET45
        // TODO - replacement on CORE
        /// <summary>
        /// Gets the quotation mark character used to enclose the attribute node. (" or ')
        /// </summary>
        public override char QuoteChar
        {
            get => _innerReader.QuoteChar;
        }
#endif
        /// <summary>
        /// Gets the InnerReader's ReadState. 
        /// </summary>
        public override ReadState ReadState
        {
            get => _innerReader.ReadState;
        }

        /// <summary>
        /// Gets the Value of the InnerReader's current node.
        /// </summary>
        public override string Value
        {
            get => _innerReader.Value;
        }

        /// <summary>
        /// Gets the ValueType of InnerReader's current node.
        /// </summary>
        public override Type ValueType
        {
            get => _innerReader.ValueType;
        }

        /// <summary>
        /// Gets the InnerReader's XmlLang.
        /// </summary>
        public override string XmlLang
        {
            get => _innerReader.XmlLang;
        }

        /// <summary>
        /// Gets the InnerReader's XmlSpace.
        /// </summary>
        public override XmlSpace XmlSpace
        {
            get => _innerReader.XmlSpace;
        }

#if DESKTOPNET45
        /// <summary>
        /// Closes the reader and changes the System.Xml.XmlReader.ReadState
        /// to Closed.
        /// </summary>
        public override void Close()
        {
            _innerReader.Close();
        }
#endif
        /// <summary>
        /// Gets the value of the InnerReader's attribute at the given index.
        /// </summary>
        /// <param name="i">The index of the attribute. The index is 0 based index.</param>
        /// <returns>The value of the attribute at the specified index.</returns>
        /// <remarks>The method does not move the reader position.</remarks>
        public override string GetAttribute(int i)
        {
            return _innerReader.GetAttribute(i);
        }

        /// <summary>
        /// Gets the value of the InnerReader's attribute with the given name.
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
        /// Gets the value of the InnerReader's attribute with the given name and namespace Uri.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="namespace">The namespace of the attribute.</param>
        /// <returns>The value of the attribute. If the attribute is not found
        /// null is returned.</returns>
        /// <remarks>The method does not move the reader.</remarks>
        public override string GetAttribute(string name, string @namespace)
        {
            return _innerReader.GetAttribute(name, @namespace);
        }

        /// <summary>
        /// Gets a value indicating if the InnerReader HasLineInfo
        /// </summary>
        public bool HasLineInfo()
        {
            var lineInfo = _innerReader as IXmlLineInfo;

            if (lineInfo == null)
                return false;

            return lineInfo.HasLineInfo();
        }

        /// <summary>
        /// Resolves the InnerReader's namespace prefix in the current element scope.
        /// </summary>
        /// <param name="prefix">Prefix whose namespace Uri to be resolved.</param>
        /// <returns>The namespace Uri to which the prefix matches or null if no matching
        /// prefix is found.</returns>
        public override string LookupNamespace(string prefix)
        {
            return _innerReader.LookupNamespace(prefix);
        }

        /// <summary>
        /// Moves to the InnerReader's attribute with the specified index.
        /// </summary>
        /// <param name="index">The index of the attribute.</param>
        public override void MoveToAttribute(int index)
        {
            _innerReader.MoveToAttribute(index);
        }

        /// <summary>
        /// Moves to the InnerReader's attribute with the given local name.
        /// </summary>
        /// <param name="name">The qualified name of the attribute.</param>
        /// <returns>true if the attribute is found; otherwise, false.</returns>
        public override bool MoveToAttribute(string name)
        {
            return _innerReader.MoveToAttribute(name);
        }

        /// <summary>
        /// Moves to the InnerReader's attribute with the specified LocalName and NamespaceURI.
        /// </summary>
        /// <param name="name">The local name of the attribute.</param>
        /// <param name="namespace">The namespace URI of the attribute.</param>
        /// <returns>true if the attribute is found; otherwise, false.</returns>
        public override bool MoveToAttribute(string name, string @namespace)
        {
            return _innerReader.MoveToAttribute(name, @namespace);
        }

        /// <summary>
        /// Moves the InnerReader to a node of type Element.
        /// </summary>
        /// <returns>true if the reader is positioned on an element else false</returns>
        public override bool MoveToElement()
        {
            return _innerReader.MoveToElement();
        }

        /// <summary>
        /// Moves the InnerReader to the first attribute.
        /// </summary>
        /// <returns>Returns true if the reader is positioned at a attribute else false.</returns>
        /// <remarks>When returning false the reader position will not be changed.</remarks>
        public override bool MoveToFirstAttribute()
        {
            return _innerReader.MoveToFirstAttribute();
        }

        /// <summary>
        /// Moves the InnerReader to the next attribute.
        /// </summary>
        /// <returns>Returns true if the reader is positioned at an attribute else false.</returns>
        /// <remarks>When returning false the reader position will not be changed.</remarks>
        public override bool MoveToNextAttribute()
        {
            return _innerReader.MoveToNextAttribute();
        }

        /// <summary>
        /// Reads the InnerReader's next node from the stream.
        /// </summary>
        /// <returns>true if the next node was read successfully.</returns>
        public override bool Read()
        {
            return _innerReader.Read();
        }

        /// <summary>
        /// Parses the InnerReader's attribute value into one or more Text, EntityReference, or EndEntity nodes.
        /// </summary>
        /// <returns>true if there are nodes to return.false if the reader is not positioned on
        /// an attribute node when the initial call is made or if all the attribute values
        /// have been read.</returns>
        public override bool ReadAttributeValue()
        {
            return _innerReader.ReadAttributeValue();
        }

        /// <summary>
        /// Reads the InnerReader's content and returns the Base64 decoded binary bytes.
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
        /// Reads the InnerReader's content and returns the BinHex decoded binary bytes.
        /// </summary>
        /// <param name="buffer">The buffer into which to copy the resulting text. This value cannot be null.</param>
        /// <param name="index">The offset into the buffer where to start copying the result.</param>
        /// <param name="count">The maximum number of bytes to copy into the buffer.</param>
        /// <returns>The number of bytes written to the buffer.</returns>
        public override int ReadContentAsBinHex(byte[] buffer, int index, int count)
        {
            return _innerReader.ReadContentAsBinHex(buffer, index, count);
        }

        /// <summary>
        /// Resolves the InnerReader's EntityReference nodes.
        /// </summary>
        public override void ResolveEntity()
        {
            _innerReader.ResolveEntity();
        }

        /// <summary>
        /// Reads large streams of text embedded in an XML document from the InnerReader.
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
