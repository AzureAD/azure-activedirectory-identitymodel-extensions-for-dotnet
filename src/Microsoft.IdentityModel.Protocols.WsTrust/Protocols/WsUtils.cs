// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Utilities for working with WS-* 
    /// </summary>
    internal static class WsUtils
    {
        /// <summary>
        /// <see cref="XmlDictionaryReaderQuotas"/> with a bounded <see cref="XmlDictionaryReaderQuotas.MaxDepth"/>
        /// (32) used when materializing buffered XML. All other limits stay at their maximum so large but
        /// shallow WS-Trust messages are unaffected. Keeps element nesting within a sane bound, consistent
        /// with the reader quotas used elsewhere in the stack.
        /// </summary>
        internal static readonly XmlDictionaryReaderQuotas BoundedReaderQuotas = new XmlDictionaryReaderQuotas
        {
            MaxArrayLength = int.MaxValue,
            MaxBytesPerRead = int.MaxValue,
            MaxDepth = 32,
            MaxNameTableCharCount = int.MaxValue,
            MaxStringContentLength = int.MaxValue,
        };

        /// <summary>
        /// Assumes the xmlreader is positioned on a start element.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static XmlElement ReadAsXmlElement(XmlDictionaryReader reader)
        {
            XmlElement xmlElement = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (XmlWriter writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    writer.WriteNode(reader, true);
                    writer.Flush();
                }

                ms.Seek(0, SeekOrigin.Begin);
                if (ms.Length == 0)
                    return null;

                using (var memoryReader = XmlDictionaryReader.CreateTextReader(ms, Encoding.UTF8, BoundedReaderQuotas, null))
                {
                    XmlDocument dom = new XmlDocument
                    {
                        PreserveWhitespace = true,
                        XmlResolver = null
                    };

                    dom.Load(memoryReader);
                    xmlElement = dom.DocumentElement;
                }
            }

            return xmlElement;
        }

        /// <summary>
        /// Helper method to read a element string
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static string ReadStringElement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsEmptyElement)
            {
                reader.ReadStartElement();
                return null;
            }

            reader.ReadStartElement();
            var strVal = reader.ReadContentAsString();
            reader.MoveToContent();
            reader.ReadEndElement();

            return strVal;
        }

        /// <summary>
        /// Helper method to read an int element
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static int? ReadIntElement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsEmptyElement)
            {
                reader.ReadStartElement();
                return null;
            }

            reader.ReadStartElement();
            var intVal = reader.ReadContentAsInt();
            reader.MoveToContent();
            reader.ReadEndElement();

            return intVal;
        }

        /// <summary>
        /// Checks standard items on a write call.
        /// </summary>
        internal static void ValidateParamsForWritting(XmlWriter writer, WsSerializationContext serializationContext, object obj, string objName)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (obj == null)
                throw LogHelper.LogArgumentNullException(objName);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        internal static void CheckReaderOnEntry(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw XmlUtil.LogReadException(LogMessages.IDX15022, reader.NodeType);
        }

        /// <summary>
        /// Checks if the <see cref="XmlReader"/> is pointing to an expected element.
        /// </summary>
        /// <param name="reader">the <see cref="XmlReader"/>to check.</param>
        /// <param name="element">the expected element.</param>
        /// <param name="serializationContext">the expected namespace.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="element"/> is null or empty.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at a StartElement.</exception>
        /// <exception cref="XmlReadException">if <paramref name="reader"/> if not at expected element.</exception>
        internal static void CheckReaderOnEntry(XmlReader reader, string element, WsSerializationContext serializationContext)
        {
            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // IsStartElement calls reader.MoveToContent().
            if (!reader.IsStartElement())
                throw XmlUtil.LogReadException(LogMessages.IDX15022, reader.NodeType);

            if (!reader.IsStartElement(element, serializationContext.TrustConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX15011, serializationContext.TrustConstants.Namespace, element, reader.NamespaceURI, reader.LocalName);
        }
    }

    /// <summary>
    /// Wraps an <see cref="XmlReader"/> and throws <see cref="System.Xml.XmlException"/> if element
    /// nesting depth exceeds the configured maximum. Does not buffer and does not own (dispose)
    /// the inner reader.
    /// </summary>
    internal sealed class DepthLimitingXmlReader : XmlReader
    {
        private readonly XmlReader _inner;
        private readonly int _maxDepth;

        internal DepthLimitingXmlReader(XmlReader inner, int maxDepth)
        {
            _inner = inner ?? throw LogHelper.LogArgumentNullException(nameof(inner));
            _maxDepth = maxDepth;
        }

        public override bool Read()
        {
            bool result = _inner.Read();
            if (_inner.Depth > _maxDepth)
                throw LogHelper.LogExceptionMessage(
                    new System.Xml.XmlException(LogHelper.FormatInvariant(LogMessages.IDX15025, _maxDepth)));

            return result;
        }

        public override int AttributeCount => _inner.AttributeCount;
        public override string BaseURI => _inner.BaseURI;
        public override int Depth => _inner.Depth;
        public override bool EOF => _inner.EOF;
        public override bool IsEmptyElement => _inner.IsEmptyElement;
        public override string LocalName => _inner.LocalName;
        public override string NamespaceURI => _inner.NamespaceURI;
        public override XmlNameTable NameTable => _inner.NameTable;
        public override XmlNodeType NodeType => _inner.NodeType;
        public override string Prefix => _inner.Prefix;
        public override ReadState ReadState => _inner.ReadState;
        public override string Value => _inner.Value;

        public override string GetAttribute(int i) => _inner.GetAttribute(i);
        public override string GetAttribute(string name) => _inner.GetAttribute(name);
        public override string GetAttribute(string name, string namespaceURI) => _inner.GetAttribute(name, namespaceURI);
        public override string LookupNamespace(string prefix) => _inner.LookupNamespace(prefix);
        public override bool MoveToAttribute(string name) => _inner.MoveToAttribute(name);
        public override bool MoveToAttribute(string name, string ns) => _inner.MoveToAttribute(name, ns);
        public override bool MoveToElement() => _inner.MoveToElement();
        public override bool MoveToFirstAttribute() => _inner.MoveToFirstAttribute();
        public override bool MoveToNextAttribute() => _inner.MoveToNextAttribute();
        public override bool ReadAttributeValue() => _inner.ReadAttributeValue();
        public override void ResolveEntity() => _inner.ResolveEntity();
    }
}
