// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustParserRegressionTests
    {
        private const string TrustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

        [Fact]
        public async Task ReadRequestedProofToken_UnknownChild_AdvancesReader()
        {
            using XmlDictionaryReader reader = CreateReader(
                $"<root xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                "<wst:RequestedProofToken><ext:Unknown/></wst:RequestedProofToken><after/></root>");
            reader.ReadStartElement("root");

            Task<RequestedProofToken> readTask = Task.Run(
                () => WsTrustSerializer.ReadRequestedProofToken(reader, new WsSerializationContext(WsTrustVersion.Trust13)));

            Task completedTask = await Task.WhenAny(readTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(readTask, completedTask);
            Assert.NotNull(await readTask);
            Assert.True(reader.IsStartElement("after"));
        }

        [Fact]
        public async Task ReadRequest_EmptyEndpointReferenceExtension_ContinuesParsing()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" " +
                "xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                "xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:ext=\"urn:extension\">" +
                "<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>https://example.com</wsa:Address>" +
                "<ext:Extension/></wsa:EndpointReference></wsp:AppliesTo>" +
                "<wst:TokenType>token-type</wst:TokenType></wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            Task<WsTrustRequest> readTask = Task.Run(() => serializer.ReadRequest(CreateReader(xml)));

            Task completedTask = await Task.WhenAny(readTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(readTask, completedTask);
            WsTrustRequest request = await readTask;
            Assert.Equal("token-type", request.TokenType);
            Assert.Single(request.AppliesTo.EndpointReference.AdditionalXmlElements);
        }

        [Fact]
        public async Task ReadResponse_UnknownAppliesToAfterKnownAppliesTo_ContinuesParsing()
        {
            string xml =
                $"<root xmlns:wst=\"{TrustNamespace}\" " +
                "xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" " +
                "xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:ext=\"urn:extension\">" +
                "<wst:RequestSecurityTokenResponse>" +
                "<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>https://example.com</wsa:Address>" +
                "</wsa:EndpointReference></wsp:AppliesTo>" +
                "<ext:AppliesTo/><wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityTokenResponse><after/></root>";
            using XmlDictionaryReader reader = CreateReader(xml);
            reader.ReadStartElement("root");
            var serializer = new WsTrustSerializer();

            Task<RequestSecurityTokenResponse> readTask = Task.Run(
                () => serializer.ReadRequestSeurityTokenResponse(
                    reader,
                    new WsSerializationContext(WsTrustVersion.Trust13)));

            Task completedTask = await Task.WhenAny(readTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(readTask, completedTask);
            Assert.Equal("token-type", (await readTask).TokenType);
            Assert.True(reader.IsStartElement("after"));
        }

        [Fact]
        public void ReadRequest_NonEmptyExtension_ContinuesParsing()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                "<ext:Extension><ext:Value>value</ext:Value></ext:Extension>" +
                "<wst:TokenType>token-type</wst:TokenType></wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal("token-type", request.TokenType);
            Assert.Single(request.AdditionalXmlElements);
            Assert.Equal("Extension", request.AdditionalXmlElements[0].LocalName);
        }

        [Fact]
        public void ReadRequest_AdditionalAttributes_PreserveValuesWithoutContextOrNamespaceDeclarations()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\" " +
                "Context=\"context\" custom=\"value\" ext:qualified=\"qualified-value\"/>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal("context", request.Context);
            Assert.Equal(2, request.AdditionalXmlAttributes.Count);
            Assert.Equal("value", request.AdditionalXmlAttributes.Single(attribute => attribute.LocalName == "custom").Value);
            Assert.Equal(
                "qualified-value",
                request.AdditionalXmlAttributes.Single(attribute => attribute.LocalName == "qualified").Value);
            Assert.DoesNotContain(request.AdditionalXmlAttributes, attribute => attribute.LocalName == "Context");
            Assert.DoesNotContain(
                request.AdditionalXmlAttributes,
                attribute => attribute.Prefix == "xmlns" || attribute.LocalName == "xmlns");

            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
            serializer.WriteRequest(writer, WsTrustVersion.Trust13, request);
            writer.Flush();

            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(Encoding.UTF8.GetString(stream.ToArray()));
            Assert.Equal("context", document.DocumentElement.GetAttribute("Context"));
            Assert.Equal("value", document.DocumentElement.GetAttribute("custom"));
            Assert.Equal("qualified-value", document.DocumentElement.GetAttribute("qualified", "urn:extension"));
        }

        [Fact]
        public void ReadAdditionalContext_EmptyContextItem_DoesNotConsumeFollowingItem()
        {
            const string authNamespace = "http://docs.oasis-open.org/wsfed/authorization/200706";
            string xml =
                $"<auth:AdditionalContext xmlns:auth=\"{authNamespace}\">" +
                "<auth:ContextItem Name=\"first\" Scope=\"scope\"/>" +
                "<auth:ContextItem Name=\"second\" Scope=\"scope\"><auth:Value>value</auth:Value></auth:ContextItem>" +
                "</auth:AdditionalContext>";
            using XmlDictionaryReader reader = CreateReader(xml);
            var serializer = new WsFedSerializer();

            AdditionalContext context = serializer.ReadAdditionalContext(reader, authNamespace);

            Assert.Equal(2, context.Items.Count);
            Assert.Equal("first", context.Items[0].Name);
            Assert.Null(context.Items[0].Value);
            Assert.Equal("second", context.Items[1].Name);
            Assert.Equal("value", context.Items[1].Value);
        }

        [Fact]
        public void ReadRequest_EmptyContainers_DoNotConsumeFollowingElements()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" " +
                "xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\">" +
                "<wst:Claims Dialect=\"urn:dialect\"/><auth:AdditionalContext/>" +
                "<wst:TokenType>token-type</wst:TokenType></wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Empty(request.Claims.ClaimTypes);
            Assert.Empty(request.AdditionalContext.Items);
            Assert.Equal("token-type", request.TokenType);
        }

        [Fact]
        public void ReadResponse_EmptyChildContainers_DoNotConsumeFollowingElements()
        {
            string xml =
                $"<wst:RequestSecurityTokenResponse xmlns:wst=\"{TrustNamespace}\">" +
                "<wst:Lifetime/><wst:Entropy/><wst:RequestedProofToken/>" +
                "<wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityTokenResponse>";
            var serializer = new WsTrustSerializer();

            RequestSecurityTokenResponse response = serializer.ReadRequestSeurityTokenResponse(
                CreateReader(xml),
                new WsSerializationContext(WsTrustVersion.Trust13));

            Assert.NotNull(response.Lifetime);
            Assert.NotNull(response.Entropy);
            Assert.NotNull(response.RequestedProofToken);
            Assert.Equal("token-type", response.TokenType);
        }

        [Fact]
        public void ReadResponse_EmptyResponseInCollection_DoesNotConsumeFollowingResponse()
        {
            string xml =
                $"<wst:RequestSecurityTokenResponseCollection xmlns:wst=\"{TrustNamespace}\">" +
                "<wst:RequestSecurityTokenResponse/>" +
                "<wst:RequestSecurityTokenResponse><wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityTokenResponse>" +
                "</wst:RequestSecurityTokenResponseCollection>";
            var serializer = new WsTrustSerializer();

            WsTrustResponse response = serializer.ReadResponse(CreateReader(xml));

            Assert.Equal(2, response.RequestSecurityTokenResponseCollection.Count);
            Assert.Null(response.RequestSecurityTokenResponseCollection[0].TokenType);
            Assert.Equal("token-type", response.RequestSecurityTokenResponseCollection[1].TokenType);
        }

        [Fact]
        public void ReadEndpointReference_EmptyElement_DoesNotConsumeFollowingSibling()
        {
            const string addressingNamespace = "http://www.w3.org/2005/08/addressing";
            using XmlDictionaryReader reader = CreateReader(
                $"<root xmlns:wsa=\"{addressingNamespace}\"><wsa:EndpointReference/><after/></root>");
            reader.ReadStartElement("root");
            var serializer = new WsAddressingSerializer();

            Assert.Throws<XmlReadException>(() => serializer.ReadEndpointReference(reader));
            Assert.True(reader.IsStartElement("after"));
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }
    }
}
