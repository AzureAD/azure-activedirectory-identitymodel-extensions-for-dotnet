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
        internal const int MaxBufferedXmlSize = 4 * 1024 * 1024;
        internal const int MaxElementCount = 4096;
        internal const int MaxAttributeCount = 4096;
        internal const int MaxXmlCharacters = 4 * 1024 * 1024;
        [ThreadStatic]
        private static ReadBudget t_readBudget;
        [ThreadStatic]
        private static int t_readScopeDepth;

        /// <summary>
        /// <see cref="XmlDictionaryReaderQuotas"/> used when materializing buffered XML.
        /// </summary>
        internal static readonly XmlDictionaryReaderQuotas BoundedReaderQuotas = new XmlDictionaryReaderQuotas
        {
            MaxArrayLength = MaxBufferedXmlSize,
            MaxBytesPerRead = 4096,
            MaxDepth = 32,
            MaxNameTableCharCount = 64 * 1024,
            MaxStringContentLength = MaxBufferedXmlSize,
        };

        internal static MemoryStream CreateBoundedMemoryStream()
        {
            return new BoundedMemoryStream(MaxBufferedXmlSize);
        }

        internal static void AddAttributeCount(int count)
        {
            t_readBudget?.AddAttributes(count);
        }

        internal static void AddXmlCharacters(int count)
        {
            t_readBudget?.AddCharacters(count);
        }

        internal static void AddElementCount(int count)
        {
            t_readBudget?.AddElements(count);
        }

        internal static IDisposable EnterReadScope()
        {
            if (t_readScopeDepth == 0)
                t_readBudget = new ReadBudget();

            t_readScopeDepth++;
            return new ReadScope();
        }

        internal static void EnsureElementCount(int elementCount)
        {
            if (elementCount > MaxElementCount)
                throw LogHelper.LogExceptionMessage(
                    new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15026, "element count", MaxElementCount)));

            AddElementCount(1);
        }

        internal static void SkipElement(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement())
                throw XmlUtil.LogReadException(LogMessages.IDX15022, reader.NodeType);

            bool isEmptyElement = reader.IsEmptyElement;
            using (var boundedReader = new DepthLimitingXmlReader(reader.ReadSubtree(), BoundedReaderQuotas.MaxDepth, false))
            {
                while (boundedReader.Read())
                {
                }
            }

            if (isEmptyElement)
                reader.Read();
            else
                reader.ReadEndElement();
        }

        /// <summary>
        /// Assumes the xmlreader is positioned on a start element.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        internal static XmlElement ReadAsXmlElement(XmlDictionaryReader reader)
        {
            XmlElement xmlElement = null;
            using (MemoryStream ms = CreateBoundedMemoryStream())
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
                using (var depthLimitingReader = new DepthLimitingXmlReader(memoryReader, BoundedReaderQuotas.MaxDepth))
                {
                    XmlDocument dom = new XmlDocument
                    {
                        PreserveWhitespace = true,
                        XmlResolver = null
                    };

                    dom.Load(depthLimitingReader);
                    xmlElement = dom.DocumentElement;
                }
            }

            return xmlElement;
        }

        private sealed class BoundedMemoryStream : MemoryStream
        {
            private readonly long _maxLength;

            internal BoundedMemoryStream(long maxLength)
            {
                _maxLength = maxLength;
            }

            public override void SetLength(long value)
            {
                EnsureCapacityForLength(value);
                t_readBudget?.AddBufferedBytes(Math.Max(0, value - Length));
                base.SetLength(value);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                long newLength = Math.Max(Length, Position + count);
                EnsureCapacityForLength(newLength);
                t_readBudget?.AddBufferedBytes(newLength - Length);
                base.Write(buffer, offset, count);
            }

            public override void WriteByte(byte value)
            {
                long newLength = Math.Max(Length, Position + 1);
                EnsureCapacityForLength(newLength);
                t_readBudget?.AddBufferedBytes(newLength - Length);
                base.WriteByte(value);
            }

            private void EnsureCapacityForLength(long length)
            {
                if (length > _maxLength)
                    throw LogHelper.LogExceptionMessage(
                        new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15026, "buffered XML bytes", _maxLength)));
            }
        }

        private sealed class ReadBudget
        {
            private int _attributeCount;
            private long _bufferedBytes;
            private int _elementCount;
            private long _xmlCharacters;

            internal void AddAttributes(int count)
            {
                _attributeCount += count;
                if (_attributeCount > MaxAttributeCount)
                    ThrowResourceLimit("attribute count", MaxAttributeCount);
            }

            internal void AddBufferedBytes(long count)
            {
                _bufferedBytes += count;
                if (_bufferedBytes > MaxBufferedXmlSize)
                    ThrowResourceLimit("buffered XML bytes", MaxBufferedXmlSize);
            }

            internal void AddCharacters(int count)
            {
                _xmlCharacters += count;
                if (_xmlCharacters > MaxXmlCharacters)
                    ThrowResourceLimit("XML characters", MaxXmlCharacters);
            }

            internal void AddElements(int count)
            {
                _elementCount += count;
                if (_elementCount > MaxElementCount)
                    ThrowResourceLimit("element count", MaxElementCount);
            }
        }

        private sealed class ReadScope : IDisposable
        {
            private bool _disposed;

            public void Dispose()
            {
                if (_disposed)
                    return;

                _disposed = true;
                t_readScopeDepth--;
                if (t_readScopeDepth == 0)
                    t_readBudget = null;
            }
        }

        private static void ThrowResourceLimit(string resource, int limit)
        {
            throw LogHelper.LogExceptionMessage(
                new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15026, resource, limit)));
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
            var value = new StringBuilder();
            var buffer = new char[4096];
            while (true)
            {
                if (reader.NodeType == XmlNodeType.Text ||
                    reader.NodeType == XmlNodeType.CDATA ||
                    reader.NodeType == XmlNodeType.Whitespace ||
                    reader.NodeType == XmlNodeType.SignificantWhitespace)
                {
                    int read;
                    while ((read = reader.ReadValueChunk(buffer, 0, buffer.Length)) > 0)
                    {
                        AddXmlCharacters(read);
                        if (value.Length + read > MaxXmlCharacters)
                            ThrowResourceLimit("string content characters", MaxXmlCharacters);

                        value.Append(buffer, 0, read);
                    }

                    reader.Read();
                    continue;
                }

                if (reader.NodeType == XmlNodeType.Comment ||
                    reader.NodeType == XmlNodeType.ProcessingInstruction)
                {
                    reader.Read();
                    continue;
                }

                break;
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return value.ToString();
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
        private readonly bool _countRootElement;
        private readonly int _maxDepth;
        private int _elementCount;

        internal DepthLimitingXmlReader(XmlReader inner, int maxDepth)
            : this(inner, maxDepth, true)
        {
        }

        internal DepthLimitingXmlReader(XmlReader inner, int maxDepth, bool countRootElement)
        {
            _inner = inner ?? throw LogHelper.LogArgumentNullException(nameof(inner));
            _maxDepth = maxDepth;
            _countRootElement = countRootElement;
        }

        public override bool Read()
        {
            bool result = _inner.Read();
            if (!result)
                return false;

            if (_inner.Depth > _maxDepth)
                throw LogHelper.LogExceptionMessage(
                    new System.Xml.XmlException(LogHelper.FormatInvariant(LogMessages.IDX15025, _maxDepth)));

            if (_inner.NodeType == XmlNodeType.Element)
            {
                _elementCount++;
                if (_elementCount > WsUtils.MaxElementCount)
                    ThrowResourceLimit("element count", WsUtils.MaxElementCount);

                if (_countRootElement || _elementCount > 1)
                    WsUtils.AddElementCount(1);

                WsUtils.AddAttributeCount(_inner.AttributeCount);

                AddCharacters(_inner.LocalName);
                AddCharacters(_inner.NamespaceURI);
                for (int i = 0; i < _inner.AttributeCount; i++)
                {
                    AddCharacters(_inner.GetAttribute(i));
                }
            }
            else if (_inner.HasValue)
            {
                AddCharacters(_inner.Value);
            }

            return true;
        }

        private static void AddCharacters(string value)
        {
            if (value == null)
                return;

            WsUtils.AddXmlCharacters(value.Length);
        }

        private static void ThrowResourceLimit(string resource, int limit)
        {
            throw LogHelper.LogExceptionMessage(
                new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15026, resource, limit)));
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
