// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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

        private static void AssertResourceLimit(Action action)
        {
            Exception exception = Assert.ThrowsAny<Exception>(action);
            Assert.StartsWith("IDX15026:", exception.Message, StringComparison.Ordinal);
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }
    }
}
