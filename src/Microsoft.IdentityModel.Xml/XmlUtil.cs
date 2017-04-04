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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public static class XmlUtil
    {
        public const string LanguagePrefix = "xml";
        public const string LanguageLocalname = "lang";
        public const string LanguageAttribute = LanguagePrefix + ":" + LanguageLocalname;
        public const string XmlNs = "http://www.w3.org/XML/1998/namespace";
        public const string XmlNsNs = "http://www.w3.org/2000/xmlns/";

        public static void CheckReaderOnEntry(XmlReader reader, string element, string ns, bool allowEmptyElement = false)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (!allowEmptyElement && reader.IsEmptyElement)
                throw LogReadException(LogMessages.IDX11104, element);

            if (!reader.IsStartElement(element, ns))
                throw LogReadException(LogMessages.IDX11105, reader.LocalName);
        }

        public static bool EqualsQName(XmlQualifiedName qname, string localName, string namespaceUri)
        {
            return null != qname
                && StringComparer.Ordinal.Equals(localName, qname.Name)
                && StringComparer.Ordinal.Equals(namespaceUri, qname.Namespace);
        }

        internal static System.Xml.UniqueId GetAttributeAsUniqueId(XmlDictionaryReader reader, string name, string ns)
        {
            if (!reader.MoveToAttribute(name, ns))
            {
                return null;
            }

            System.Xml.UniqueId id = reader.ReadContentAsUniqueId();
            reader.MoveToElement();

            return id;
        }

        internal static string GetWhiteSpace(XmlReader reader)
        {
            string s = null;
            StringBuilder sb = null;
            while (reader.NodeType == XmlNodeType.Whitespace || reader.NodeType == XmlNodeType.SignificantWhitespace)
            {
                if (sb != null)
                {
                    sb.Append(reader.Value);
                }
                else if (s != null)
                {
                    sb = new StringBuilder(s);
                    sb.Append(reader.Value);
                    s = null;
                }
                else
                {
                    s = reader.Value;
                }
                if (!reader.Read())
                {
                    break;
                }
            }
            return sb != null ? sb.ToString() : s;
        }

        // Takes a collection of node list and returns a list of XmlElements
        // from the list (skipping past any XmlComments and CDATA nodes).
        public static List<XmlElement> GetXmlElements(XmlNodeList nodeList)
        {
            if (nodeList == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(nodeList));
            }

            List<XmlElement> xmlElements = new List<XmlElement>();
            foreach (XmlNode node in nodeList)
            {
                XmlElement tempElement = node as XmlElement;
                if (tempElement != null)
                {
                    xmlElements.Add(tempElement);
                }
            }

            return xmlElements;
        }

        public static XmlQualifiedName GetXsiType(XmlReader reader)
        {
            string xsiType = reader.GetAttribute("type", XmlSchema.InstanceNamespace);
            reader.MoveToElement();

            if (string.IsNullOrEmpty(xsiType))
            {
                return null;
            }

            return ResolveQName(reader, xsiType);
        }

        public static bool IsNil(XmlReader reader)
        {
            string xsiNil = reader.GetAttribute("nil", XmlSchema.InstanceNamespace);
            return !string.IsNullOrEmpty(xsiNil) && XmlConvert.ToBoolean(xsiNil);
        }

        public static bool IsValidXmlIDValue(string val)
        {
            if (string.IsNullOrEmpty(val))
            {
                return false;
            }

            // The first character of the ID should be a letter, '_' or ':'
            return (((val[0] >= 'A') && (val[0] <= 'Z')) ||
                ((val[0] >= 'a') && (val[0] <= 'z')) ||
                (val[0] == '_') || (val[0] == ':'));
        }

        public static bool IsWhitespace(char ch)
        {
            return (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n');
        }

        public static string NormalizeEmptyString(string s)
        {
            return string.IsNullOrEmpty(s) ? null : s;
        }

        internal static Exception OnRequiredAttributeMissing(string element, string attribute)
        {
            return LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX11106, element, attribute)));
        }

        internal static Exception OnRequiredElementMissing(string element, string ns, XmlReader reader)
        {
            return LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX11105, element, reader.LocalName)));
        }

        internal static Exception OnUnexpectedChildNode(string reading, XmlReader reader)
        {
            return LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX11106, reading, reader.LocalName)));
        }

        // TODO - localize error messages
        public static void ParseQName(XmlReader reader, string qname, out string localName, out string ns)
        {
            int index = qname.IndexOf(':');
            string prefix;
            if (index < 0)
            {
                prefix = "";
                localName = TrimStart(TrimEnd(qname));
            }
            else
            {
                if (index == qname.Length - 1)
                    throw LogHelper.LogExceptionMessage(new XmlException("InvalidXmlQualifiedName, qname"));
                prefix = TrimStart(qname.Substring(0, index));
                localName = TrimEnd(qname.Substring(index + 1));
            }
            ns = reader.LookupNamespace(prefix);
            if (ns == null)
                throw LogHelper.LogExceptionMessage(new XmlException("UnboundPrefixInQName, qname"));
        }

        public static void ReadContentAsQName(XmlReader reader, out string localName, out string ns)
        {
            ParseQName(reader, reader.ReadContentAsString(), out localName, out ns);
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

        public static Int64 ReadElementContentAsInt64(XmlDictionaryReader reader)
        {
            reader.ReadFullStartElement();
            Int64 i = reader.ReadContentAsLong();
            reader.ReadEndElement();
            return i;
        }

        internal static string ReadTextElementAsTrimmedString(XmlElement element)
        {
            if (element == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(element));
            }

            XmlReader reader = new XmlNodeReader(element);
            reader.MoveToContent();
            return XmlUtil.Trim(reader.ReadElementContentAsString());
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

        public static string SerializeSecurityKeyIdentifier(SecurityKeyIdentifier ski)
        {
            StringBuilder sb = new StringBuilder();
            using (StringWriter stringWriter = new StringWriter(sb, CultureInfo.InvariantCulture))
            {
                XmlWriterSettings settings = new XmlWriterSettings();
                settings.OmitXmlDeclaration = true;
                using (XmlWriter xmlWriter = XmlWriter.Create(stringWriter, settings))
                {
                    // TODO write out string
                    //                    tokenSerializer.WriteKeyIdentifierClause(xmlWriter, ski[0]);
                }
            }

            return sb.ToString();
        }

        public static string Trim(string s)
        {
            int i;
            for (i = 0; i < s.Length && IsWhitespace(s[i]); i++) ;
            if (i >= s.Length)
            {
                return string.Empty;
            }

            int j;
            for (j = s.Length; j > 0 && IsWhitespace(s[j - 1]); j--) ;

            if (i != 0 || j != s.Length)
            {
                return s.Substring(i, j - i);
            }
            return s;
        }

        public static string TrimEnd(string s)
        {
            int i;
            for (i = s.Length; i > 0 && IsWhitespace(s[i - 1]); i--) ;

            if (i != s.Length)
            {
                return s.Substring(0, i);
            }

            return s;
        }

        public static string TrimStart(string s)
        {
            int i;
            for (i = 0; i < s.Length && IsWhitespace(s[i]); i++) ;

            if (i != 0)
            {
                return s.Substring(i);
            }

            return s;
        }

        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace)
        {
            ValidateXsiType(reader, expectedTypeName, expectedTypeNamespace, false);
        }

        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace, bool requireDeclaration)
        {
            XmlQualifiedName declaredType = GetXsiType(reader);

            if (null == declaredType)
            {
                if (requireDeclaration)
                {
                    throw LogHelper.LogExceptionMessage(new XmlException("reader.LocalName, reader.NamespaceURI"));
                }
            }
            else if (!(StringComparer.Ordinal.Equals(expectedTypeNamespace, declaredType.Namespace)
                && StringComparer.Ordinal.Equals(expectedTypeName, declaredType.Name)))
            {
                throw LogHelper.LogExceptionMessage(new XmlException("SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace"));
                //throw LogHelper.ThrowHelperXml(reader,
                //    SR.GetString(SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace));
            }
        }

        internal static void WriteAttributeStringAsUniqueId(XmlDictionaryWriter writer, string prefix, XmlDictionaryString localName, XmlDictionaryString ns, System.Xml.UniqueId id)
        {
            writer.WriteStartAttribute(prefix, localName, ns);
            writer.WriteValue(id);
            writer.WriteEndAttribute();
        }

        public static void WriteElementStringAsUniqueId(XmlDictionaryWriter writer, XmlDictionaryString localName, XmlDictionaryString ns, string id)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(id);
            writer.WriteEndElement();
        }

        public static void WriteElementContentAsInt64(XmlDictionaryWriter writer, XmlDictionaryString localName, XmlDictionaryString ns, Int64 value)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(value);
            writer.WriteEndElement();
        }

        public static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(format, args)));
        }

    }
}