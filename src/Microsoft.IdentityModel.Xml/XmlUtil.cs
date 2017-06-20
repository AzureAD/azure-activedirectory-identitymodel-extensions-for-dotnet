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
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
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

        public static void CheckReaderOnEntry(XmlReader reader, string element, string ns)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            // IsStartElement calls MoveToContent.
            if (!reader.IsStartElement(element, ns))
                throw LogReadException(LogMessages.IDX21011, ns, element, reader.NamespaceURI, reader.LocalName);
        }


        public static bool EqualsQName(XmlQualifiedName qname, string localName, string namespaceUri)
        {
            return null != qname
                && StringComparer.Ordinal.Equals(localName, qname.Name)
                && StringComparer.Ordinal.Equals(namespaceUri, qname.Namespace);
        }

        public static XmlQualifiedName GetXsiType(XmlReader reader)
        {
            string xsiType = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            reader.MoveToElement();

            if (string.IsNullOrEmpty(xsiType))
                return null;

            return ResolveQName(reader, xsiType);
        }

        public static bool IsNil(XmlReader reader)
        {
            string xsiNil = reader.GetAttribute(XmlSignatureConstants.Attributes.Nil, XmlSignatureConstants.XmlSchemaNamespace);
            return !string.IsNullOrEmpty(xsiNil) && XmlConvert.ToBoolean(xsiNil);
        }

        public static string NormalizeEmptyString(string s)
        {
            return string.IsNullOrEmpty(s) ? null : s;
        }

        internal static Exception OnRequiredAttributeMissing(string element, string attribute)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(LogMessages.IDX21013, element, attribute)));
        }

        internal static Exception OnRequiredElementMissing(XmlReader reader, string element, string ns)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(LogMessages.IDX21011, element, ns, reader.LocalName, reader.NamespaceURI)));
        }

        internal static Exception OnUnexpectedChildNode(XmlReader reader, string reading)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(LogMessages.IDX21012, reading, reader.LocalName)));
        }

        internal static string ReadEmptyElementAndRequiredAttribute(XmlDictionaryReader reader, string name, string namespaceUri, string attributeName,
            out string prefix)
        {
            reader.MoveToStartElement(name, namespaceUri);
            prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            string value = reader.GetAttribute(attributeName, null);
            if (value == null)
            {
                OnRequiredAttributeMissing(attributeName, null);
            }
            reader.Read();

            if (!isEmptyElement)
            {
                reader.ReadEndElement();
            }
            return value;
        }

        public static XmlQualifiedName ResolveQName(XmlReader reader, string qstring)
        {
            string name = qstring;
            string prefix = String.Empty;
            string ns = null;

            int colon = qstring.IndexOf(':'); // index of char is always ordinal
            if (colon > -1)
            {
                prefix = qstring.Substring(0, colon);
                name = qstring.Substring(colon + 1, qstring.Length - (colon + 1));
            }

            ns = reader.LookupNamespace(prefix);

            return new XmlQualifiedName(name, ns);
        }

        internal static void ValidateBufferBounds(Array buffer, int offset, int count)
        {
            if (buffer == null)
                throw LogArgumentNullException(nameof(buffer));

            if (count < 0 || count > buffer.Length)
                throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(count), FormatInvariant(LogMessages.IDX20001, 0, buffer.Length)));

            if (offset < 0 || offset > buffer.Length - count)
                throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(offset), FormatInvariant(LogMessages.IDX20001, 0,  buffer.Length - count)));
        }


        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace)
        {
            ValidateXsiType(reader, expectedTypeName, expectedTypeNamespace, false);
        }

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

        public static Exception LogReadException(string format, params object[] args)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(format, args)));
        }

        public static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogExceptionMessage(new XmlReadException(FormatInvariant(format, args), inner));
        }
    }
}