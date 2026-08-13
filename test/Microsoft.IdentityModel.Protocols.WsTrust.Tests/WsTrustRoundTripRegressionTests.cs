// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustRoundTripRegressionTests
    {
        private const string TrustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        private const string WsSecurityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        [Fact]
        public void Response_ContextAttributesAndUnknownElements_RoundTrip()
        {
            string xml =
                $"<wst:RequestSecurityTokenResponse xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\" " +
                "Context=\"context\" custom=\"value\" ext:qualified=\"qualified-value\">" +
                "<ext:Extension><ext:Value>extension-value</ext:Value></ext:Extension>" +
                "<wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityTokenResponse>";
            var serializer = new WsTrustSerializer();
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            RequestSecurityTokenResponse response = serializer.ReadRequestSeurityTokenResponse(CreateReader(xml), context);

            Assert.Equal("context", response.Context);
            Assert.Equal("value", response.AdditionalXmlAttributes.Single(attribute => attribute.LocalName == "custom").Value);
            Assert.Equal(
                "qualified-value",
                response.AdditionalXmlAttributes.Single(attribute => attribute.LocalName == "qualified").Value);
            Assert.Equal("extension-value", Assert.Single(response.AdditionalXmlElements).InnerText);
            Assert.Equal("token-type", response.TokenType);

            string roundTrip = WriteXml(
                writer => serializer.WriteRequestSecurityTokenResponse(writer, WsTrustVersion.Trust13, response));
            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(roundTrip);
            Assert.Equal("context", document.DocumentElement.GetAttribute("Context"));
            Assert.Equal("value", document.DocumentElement.GetAttribute("custom"));
            Assert.Equal("qualified-value", document.DocumentElement.GetAttribute("qualified", "urn:extension"));
            Assert.Equal("extension-value", document.DocumentElement.LastChild.InnerText);
        }

        [Fact]
        public void BinarySecret_AdditionalXmlAttributes_RoundTrip()
        {
            string xml =
                $"<wst:BinarySecret xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\" " +
                "wst:Type=\"urn:type\" ext:attribute=\"value\">AQID</wst:BinarySecret>";
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            BinarySecret binarySecret = WsTrustSerializer.ReadBinarySecrect(CreateReader(xml), context);

            XmlAttribute attribute = Assert.Single(binarySecret.AdditionalXmlAttributes);
            Assert.Equal("attribute", attribute.LocalName);
            Assert.Equal("urn:extension", attribute.NamespaceURI);
            Assert.Equal("value", attribute.Value);

            string roundTrip = WriteXml(writer => WsTrustSerializer.WriteBinarySecret(writer, context, binarySecret));
            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(roundTrip);
            Assert.Equal("value", document.DocumentElement.GetAttribute("attribute", "urn:extension"));
        }

        [Fact]
        public void BinarySecret_EmptyElement_PreservesTypeWithEmptyData()
        {
            string xml =
                $"<wst:BinarySecret xmlns:wst=\"{TrustNamespace}\" wst:Type=\"urn:type\"/>";

            BinarySecret binarySecret = WsTrustSerializer.ReadBinarySecrect(
                CreateReader(xml),
                new WsSerializationContext(WsTrustVersion.Trust13));

            Assert.Equal("urn:type", binarySecret.EncodingType);
            Assert.Empty(binarySecret.Data);
        }

        [Fact]
        public void SecurityTokenReference_Usage_RoundTrips()
        {
            var reference = new SecurityTokenReference(new KeyIdentifier("identifier"))
            {
                Usage = "urn:usage"
            };
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            string xml = WriteXml(
                writer => WsTrustSerializer.WriteRequestedAttachedReference(writer, context, reference));
            SecurityTokenReference result = WsTrustSerializer.ReadRequestedAttachedReference(CreateReader(xml), context);

            Assert.Equal("urn:usage", result.Usage);
        }

        [Fact]
        public void Lifetime_WrongNamespaceChild_IsSkipped()
        {
            string xml =
                $"<wst:Lifetime xmlns:wst=\"{TrustNamespace}\" " +
                "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" " +
                "xmlns:ext=\"urn:extension\">" +
                "<ext:Created>2000-01-01T00:00:00Z</ext:Created>" +
                "<wsu:Expires>2030-01-01T00:00:00Z</wsu:Expires></wst:Lifetime>";

            Lifetime lifetime = WsTrustSerializer.ReadLifetime(
                CreateReader(xml),
                new WsSerializationContext(WsTrustVersion.Trust13));

            Assert.Null(lifetime.Created);
            Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), lifetime.Expires);
        }

        [Fact]
        public void Claims_WrongNamespaceClaimType_IsSkipped()
        {
            const string authNamespace = "http://docs.oasis-open.org/wsfed/authorization/200706";
            string xml =
                $"<wst:Claims xmlns:wst=\"{TrustNamespace}\" xmlns:auth=\"{authNamespace}\" " +
                "xmlns:ext=\"urn:extension\" Dialect=\"urn:dialect\">" +
                "<ext:ClaimType Uri=\"urn:wrong\"/><auth:ClaimType Uri=\"urn:correct\"/>" +
                "</wst:Claims>";
            var serializer = new WsTrustSerializer();

            Claims claims = serializer.ReadClaims(
                CreateReader(xml),
                new WsSerializationContext(WsTrustVersion.Trust13));

            Assert.Equal("urn:correct", Assert.Single(claims.ClaimTypes).Uri);
        }

        [Fact]
        public void Request_WrongNamespacePolicyReference_IsCapturedAsExtension()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\" xmlns:ext=\"urn:extension\">" +
                "<ext:PolicyReference/><wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest request = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal("PolicyReference", Assert.Single(request.AdditionalXmlElements).LocalName);
            Assert.Equal("token-type", request.TokenType);
        }

        [Fact]
        public void SecurityTokenReference_WrongNamespaceKeyIdentifier_IsSkipped()
        {
            string xml =
                $"<wst:RequestedAttachedReference xmlns:wst=\"{TrustNamespace}\" " +
                $"xmlns:wsse=\"{WsSecurityNamespace}\" xmlns:ext=\"urn:extension\">" +
                "<wsse:SecurityTokenReference><ext:KeyIdentifier>identifier</ext:KeyIdentifier>" +
                "<wsse:KeyIdentifier>correct-identifier</wsse:KeyIdentifier>" +
                "</wsse:SecurityTokenReference></wst:RequestedAttachedReference>";
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            SecurityTokenReference reference = WsTrustSerializer.ReadRequestedAttachedReference(CreateReader(xml), context);

            Assert.NotNull(reference);
            Assert.Equal("correct-identifier", reference.KeyIdentifier.Value);
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }

        private static string WriteXml(Action<XmlDictionaryWriter> write)
        {
            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
            write(writer);
            writer.Flush();
            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}
