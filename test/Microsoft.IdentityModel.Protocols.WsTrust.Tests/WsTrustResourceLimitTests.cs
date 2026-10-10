// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Text;
using System.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustResourceLimitTests
    {
        private const string TrustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

        [Fact]
        public void ReadRequest_LargeShallowExtension_ExceedsCharacterLimit()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                $"<ext:Extension>{new string('a', WsUtils.MaxXmlCharacters + 1)}</ext:Extension>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(() => serializer.ReadRequest(CreateReader(xml)));
        }

        [Fact]
        public void ReadRequestedSecurityToken_LargeToken_ExceedsPreBufferLimit()
        {
            string xml =
                $"<wst:RequestedSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                $"<ext:Token>{new string('a', WsUtils.MaxBufferedXmlSize)}</ext:Token>" +
                "</wst:RequestedSecurityToken>";

            AssertResourceLimit(
                () => WsTrustSerializer.ReadRequestedSecurityToken(
                    CreateReader(xml),
                    new WsSerializationContext(WsTrustVersion.Trust13)));
        }

        [Fact]
        public void ReadRequest_LargeKnownString_ExceedsCharacterLimit()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\">" +
                $"<wst:TokenType>{new string('a', WsUtils.MaxXmlCharacters + 1)}</wst:TokenType>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(() => serializer.ReadRequest(CreateReader(xml)));
        }

        [Fact]
        public void ReadBinarySecret_LargeDecodedValue_ExceedsBufferLimit()
        {
            string encoded = Convert.ToBase64String(new byte[WsUtils.MaxBufferedXmlSize + 1]);
            string xml =
                $"<wst:BinarySecret xmlns:wst=\"{TrustNamespace}\">{encoded}</wst:BinarySecret>";

            AssertResourceLimit(
                () => WsTrustSerializer.ReadBinarySecrect(
                    CreateReader(xml),
                    new WsSerializationContext(WsTrustVersion.Trust13)));
        }

        [Fact]
        public void ReadRequest_TooManyExtensions_ExceedsElementLimit()
        {
            var xml = new StringBuilder(
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">");
            for (int i = 0; i <= WsUtils.MaxElementCount; i++)
                xml.Append("<ext:Extension/>");

            xml.Append("</wst:RequestSecurityToken>");
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(() => serializer.ReadRequest(CreateReader(xml.ToString())));
        }

        [Fact]
        public void ReadRequest_TooManyAttributes_ExceedsAttributeLimit()
        {
            var xml = new StringBuilder(
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\"><ext:Extension");
            for (int i = 0; i <= WsUtils.MaxAttributeCount; i++)
                xml.Append($" a{i}=\"v\"");

            xml.Append("/></wst:RequestSecurityToken>");
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(() => serializer.ReadRequest(CreateReader(xml.ToString())));
        }

        [Fact]
        public void ReadResponse_SkippedUnknownSubtree_StillEnforcesCharacterLimit()
        {
            string xml =
                $"<wst:RequestSecurityTokenResponse xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                $"<ext:AppliesTo><ext:Value>{new string('a', WsUtils.MaxXmlCharacters + 1)}</ext:Value>" +
                "</ext:AppliesTo></wst:RequestSecurityTokenResponse>";
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(
                () => serializer.ReadRequestSeurityTokenResponse(
                    CreateReader(xml),
                    new WsSerializationContext(WsTrustVersion.Trust13)));
        }

        [Fact]
        public void ReadRequestedAttachedReference_TooManyChildren_ExceedsElementLimit()
        {
            var xml = new StringBuilder(
                $"<wst:RequestedAttachedReference xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">");
            for (int i = 0; i <= WsUtils.MaxElementCount; i++)
                xml.Append("<ext:Extension/>");

            xml.Append("</wst:RequestedAttachedReference>");

            AssertResourceLimit(
                () => WsTrustSerializer.ReadRequestedAttachedReference(
                    CreateReader(xml.ToString()),
                    new WsSerializationContext(WsTrustVersion.Trust13)));
        }

        [Fact]
        public void ReadRequest_KnownStringWithComment_PreservesText()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\">" +
                "<wst:TokenType>first<!--comment-->second</wst:TokenType>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal("firstsecond", request.TokenType);
        }

        [Fact]
        public void ReadAsXmlElement_DoesNotUseEagerValueOrGetAttribute()
        {
            const string xml = "<ext:Extension xmlns:ext=\"urn:extension\" attribute=\"value\">text</ext:Extension>";
            using XmlReader innerReader = XmlReader.Create(new StringReader(xml));
            using var guardedReader = new EagerAccessGuardXmlReader(innerReader);
            guardedReader.MoveToContent();
            using IDisposable readScope = WsUtils.EnterReadScope();

            XmlElement element = WsUtils.ReadAsXmlElement(guardedReader);

            Assert.Equal("value", element.GetAttribute("attribute"));
            Assert.Equal("text", element.InnerText);
        }

        [Fact]
        public void ReadRequest_LargeExtensionAttribute_ExceedsCharacterLimit()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                $"<ext:Extension attribute=\"{new string('a', WsUtils.MaxXmlCharacters + 1)}\"/>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            AssertResourceLimit(() => serializer.ReadRequest(CreateReader(xml)));
        }

        [Fact]
        public void ReadRequest_ExtensionTextAcrossChunkBoundary_RoundTrips()
        {
            string value = new string('a', 4097);
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                $"<ext:Extension>{value}</ext:Extension></wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal(value, Assert.Single(request.AdditionalXmlElements).InnerText);
        }

        [Fact]
        public void ReadRequest_ExtensionSpecialNodes_RoundTrip()
        {
            string xml =
                "<ext:Extension xmlns:ext=\"urn:extension\"><!--comment--><![CDATA[<content>]]></ext:Extension>";
            using XmlReader reader = XmlReader.Create(new StringReader(xml));
            reader.MoveToContent();
            using IDisposable readScope = WsUtils.EnterReadScope();

            XmlElement extension = WsUtils.ReadAsXmlElement(reader);

            Assert.Equal(XmlNodeType.Comment, extension.ChildNodes[0].NodeType);
            Assert.Equal(XmlNodeType.CDATA, extension.ChildNodes[1].NodeType);
            Assert.Equal("<content>", extension.ChildNodes[1].Value);
        }

        private static void AssertResourceLimit(Action action)
        {
            Exception exception = Assert.ThrowsAny<Exception>(action);
            Assert.StartsWith("IDX15026:", exception.Message, StringComparison.Ordinal);
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }

        private sealed class EagerAccessGuardXmlReader : XmlReader
        {
            private readonly XmlReader _inner;

            internal EagerAccessGuardXmlReader(XmlReader inner)
            {
                _inner = inner;
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
            public override string Value => throw new InvalidOperationException("Eager Value access is not allowed.");

            public override string GetAttribute(int i) => throw new InvalidOperationException("Eager attribute access is not allowed.");
            public override string GetAttribute(string name) => throw new InvalidOperationException("Eager attribute access is not allowed.");
            public override string GetAttribute(string name, string namespaceURI) => throw new InvalidOperationException("Eager attribute access is not allowed.");
            public override string LookupNamespace(string prefix) => _inner.LookupNamespace(prefix);
            public override bool MoveToAttribute(string name) => _inner.MoveToAttribute(name);
            public override bool MoveToAttribute(string name, string ns) => _inner.MoveToAttribute(name, ns);
            public override void MoveToAttribute(int i) => _inner.MoveToAttribute(i);
            public override bool MoveToElement() => _inner.MoveToElement();
            public override bool MoveToFirstAttribute() => _inner.MoveToFirstAttribute();
            public override bool MoveToNextAttribute() => _inner.MoveToNextAttribute();
            public override bool Read() => _inner.Read();
            public override bool ReadAttributeValue() => _inner.ReadAttributeValue();
            public override int ReadValueChunk(char[] buffer, int index, int count) => _inner.ReadValueChunk(buffer, index, count);
            public override void ResolveEntity() => _inner.ResolveEntity();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                    _inner.Dispose();

                base.Dispose(disposing);
            }
        }
    }
}
