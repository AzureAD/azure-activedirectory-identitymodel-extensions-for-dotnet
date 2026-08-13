// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustTokenElementTests
    {
        private const string TrustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

        [Fact]
        public void OnBehalfOf_SecurityTokenReference_RoundTrips()
        {
            SecurityTokenReference reference = CreateSecurityTokenReference();
            var serializer = new WsTrustSerializer();
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            string xml = WriteXml(
                writer => serializer.WriteOnBehalfOf(writer, context, new SecurityTokenElement(reference)));
            using XmlDictionaryReader reader = CreateReader(xml);
            SecurityTokenElement result = serializer.ReadOnBehalfOf(reader, context);

            Assert.Equal("identifier", result.SecurityTokenReference.KeyIdentifier.Value);
        }

        [Fact]
        public void ProofEncryption_SecurityTokenReference_RoundTripsInRequest()
        {
            var request = new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue)
            {
                ProofEncryption = new SecurityTokenElement(CreateSecurityTokenReference())
            };
            var serializer = new WsTrustSerializer();

            string xml = WriteXml(writer => serializer.WriteRequest(writer, WsTrustVersion.Trust13, request));
            WsTrustRequest result = serializer.ReadRequest(CreateReader(xml));

            Assert.Equal("identifier", result.ProofEncryption.SecurityTokenReference.KeyIdentifier.Value);
        }

        [Fact]
        public void ProofEncryption_EmptyElement_PreservesExistingSkipBehavior()
        {
            string xml =
                $"<wst:RequestSecurityToken xmlns:wst=\"{TrustNamespace}\">" +
                "<wst:ProofEncryption/><wst:TokenType>token-type</wst:TokenType>" +
                "</wst:RequestSecurityToken>";
            var serializer = new WsTrustSerializer();

            WsTrustRequest result = serializer.ReadRequest(CreateReader(xml));

            Assert.Null(result.ProofEncryption);
            Assert.Equal("token-type", result.TokenType);
        }

        [Fact]
        public void UseKey_SecurityToken_RoundTrips()
        {
            SecurityToken token = CreateSaml2Token();
            var useKey = new UseKey(new SecurityTokenElement(token));
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            string xml = WriteXml(writer => WsTrustSerializer.WriteUseKey(writer, context, useKey));
            UseKey result = WsTrustSerializer.ReadUseKey(CreateReader(xml), context);

            Assert.IsType<Saml2SecurityToken>(result.SecurityTokenElement.SecurityToken);
        }

        [Fact]
        public void RequestedSecurityToken_SecurityToken_WritesToken()
        {
            var serializer = new WsTrustSerializer();
            var context = new WsSerializationContext(WsTrustVersion.Trust13);
            var requestedToken = new RequestedSecurityToken(CreateSaml2Token());

            string xml = WriteXml(writer => serializer.WriteRequestedSecurityToken(writer, context, requestedToken));

            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(xml);
            Assert.Equal("Assertion", document.DocumentElement.FirstChild.LocalName);
            Assert.Equal(Saml2Constants.Namespace, document.DocumentElement.FirstChild.NamespaceURI);
        }

        [Fact]
        public void OnBehalfOf_UnsupportedParsedElement_RoundTripsRawXml()
        {
            const string addressingNamespace = "http://www.w3.org/2005/08/addressing";
            string xml =
                $"<wst:OnBehalfOf xmlns:wst=\"{TrustNamespace}\" xmlns:wsa=\"{addressingNamespace}\">" +
                "<wsa:EndpointReference><wsa:Address>https://example.com</wsa:Address>" +
                "</wsa:EndpointReference></wst:OnBehalfOf>";
            var serializer = new WsTrustSerializer();
            var context = new WsSerializationContext(WsTrustVersion.Trust13);

            SecurityTokenElement tokenElement = serializer.ReadOnBehalfOf(CreateReader(xml), context);
            string roundTrip = WriteXml(writer => serializer.WriteOnBehalfOf(writer, context, tokenElement));

            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(roundTrip);
            Assert.Equal("EndpointReference", document.DocumentElement.FirstChild.LocalName);
            Assert.Equal(addressingNamespace, document.DocumentElement.FirstChild.NamespaceURI);
        }

        private static SecurityTokenReference CreateSecurityTokenReference()
        {
            return new SecurityTokenReference(new KeyIdentifier("identifier"));
        }

        private static SecurityToken CreateSaml2Token()
        {
            var handler = new Saml2SecurityTokenHandler();
            return handler.CreateToken(Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials));
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }

        private static string WriteXml(System.Action<XmlDictionaryWriter> write)
        {
            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
            write(writer);
            writer.Flush();
            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}
