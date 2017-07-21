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
    /// Utilities for working with XML
    /// </summary>
    public static class XmlUtil
    {
        /// <summary>
        /// Throws if Reader is on an empty element.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> to check.</param>
        /// <param name="element">the xml element expected.</param>
        /// <exception cref="ArgumentNullException">If 'reader' is null.</exception>
        public static void ThrowIfReaderIsOnEmptyElement(XmlReader reader, string element)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            throw LogReadException(LogMessages.IDX21010, element);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <param name="element">the expected element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="element"/> is null or empty.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at at expected element.</exception>
        public static void CheckReaderOnEntry(XmlReader reader, string element)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            if (string.IsNullOrEmpty(element))
                throw LogArgumentNullException(nameof(element));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw LogReadException(LogMessages.IDX21022, reader.NodeType);

            if (!string.Equals(reader.LocalName, element, StringComparison.OrdinalIgnoreCase))
                throw LogReadException(LogMessages.IDX21024, element, reader.LocalName);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <param name="element">the expected element.</param>
        /// <param name="namespace">the expected namespace.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="element"/> is null or empty.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at expected element.</exception>
        public static void CheckReaderOnEntry(XmlReader reader, string element, string @namespace)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw LogReadException(LogMessages.IDX21022, reader.NodeType);

            // IsStartElement calls reader.MoveToContent().
            if (string.IsNullOrEmpty(@namespace))
            {
                if (!reader.IsStartElement(element))
                    throw LogReadException(LogMessages.IDX21024, element, reader.LocalName);
            }
            else
            {
                if (!reader.IsStartElement(element, @namespace))
                    throw LogReadException(LogMessages.IDX21011, @namespace, element, reader.NamespaceURI, reader.LocalName);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="qname"></param>
        /// <param name="localName"></param>
        /// <param name="namespace"></param>
        /// <returns></returns>
        public static bool EqualsQName(XmlQualifiedName qname, string localName, string @namespace)
        {
            return null != qname
                && StringComparer.Ordinal.Equals(localName, qname.Name)
                && StringComparer.Ordinal.Equals(@namespace, qname.Namespace);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static XmlQualifiedName GetXsiType(XmlReader reader)
        {
            string xsiType = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            reader.MoveToElement();

            if (string.IsNullOrEmpty(xsiType))
                return null;

            return ResolveQName(reader, xsiType);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static bool IsNil(XmlReader reader)
        {
            string xsiNil = reader.GetAttribute(XmlSignatureConstants.Attributes.Nil, XmlSignatureConstants.XmlSchemaNamespace);
            return !string.IsNullOrEmpty(xsiNil) && XmlConvert.ToBoolean(xsiNil);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static string NormalizeEmptyString(string s)
        {
            return string.IsNullOrEmpty(s) ? null : s;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="element"></param>
        /// <param name="attribute"></param>
        /// <returns></returns>
        internal static Exception OnRequiredAttributeMissing(string element, string attribute)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(LogMessages.IDX21013, element, attribute)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="qstring"></param>
        /// <returns></returns>
        public static XmlQualifiedName ResolveQName(XmlReader reader, string qstring)
        {
            string name = qstring;
            string prefix = String.Empty;
            string @namespace = null;

            int colon = qstring.IndexOf(':'); // index of char is always ordinal
            if (colon > -1)
            {
                prefix = qstring.Substring(0, colon);
                name = qstring.Substring(colon + 1, qstring.Length - (colon + 1));
            }

            @namespace = reader.LookupNamespace(prefix);

            return new XmlQualifiedName(name, @namespace);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        internal static void ValidateBufferBounds(Array buffer, int offset, int count)
        {
            if (buffer == null)
                throw LogArgumentNullException(nameof(buffer));

            if (count < 0 || count > buffer.Length)
                throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(count), FormatInvariant(LogMessages.IDX20001, 0, buffer.Length)));

            if (offset < 0 || offset > buffer.Length - count)
                throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(offset), FormatInvariant(LogMessages.IDX20001, 0,  buffer.Length - count)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="expectedTypeName"></param>
        /// <param name="expectedTypeNamespace"></param>
        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace)
        {
            ValidateXsiType(reader, expectedTypeName, expectedTypeNamespace, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="expectedTypeName"></param>
        /// <param name="expectedTypeNamespace"></param>
        /// <param name="requireDeclaration"></param>
        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace, bool requireDeclaration)
        {
            XmlQualifiedName declaredType = GetXsiType(reader);

            if (declaredType == null)
            {
                if (requireDeclaration)
                {
                    throw LogExceptionMessage(new XmlException("reader.LocalName, reader.NamespaceURI"));
                }
            }
            else if (!(StringComparer.Ordinal.Equals(expectedTypeNamespace, declaredType.Namespace)
                && StringComparer.Ordinal.Equals(expectedTypeName, declaredType.Name)))
            {
                throw LogExceptionMessage(new XmlException("SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace"));
                //throw LogHelper.ThrowHelperXml(reader,
                //    SR.GetString(SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="format"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static Exception LogReadException(string format, params object[] args)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(format, args)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="format"></param>
        /// <param name="inner"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(format, args), inner));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="format"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static Exception LogWriteException(string format, params object[] args)
        {
            return LogExceptionMessage(new XmlWriteException(FormatInvariant(format, args)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="format"></param>
        /// <param name="inner"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static Exception LogWriteException(string format, Exception inner, params object[] args)
        {
            return LogExceptionMessage(new XmlWriteException(FormatInvariant(format, args), inner));
        }
    }
}