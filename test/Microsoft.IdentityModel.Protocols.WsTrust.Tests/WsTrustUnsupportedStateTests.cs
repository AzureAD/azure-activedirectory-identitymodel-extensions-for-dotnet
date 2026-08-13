// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.XmlEnc;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustUnsupportedStateTests
    {
        private const string TrustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        private const string XmlEncryptionNamespace = "http://www.w3.org/2001/04/xmlenc#";

        [Fact]
        public void RequestedProofToken_ParsedEncryptedKey_RoundTripsSourceXml()
        {
            string xml =
                $"<wst:RequestedProofToken xmlns:wst=\"{TrustNamespace}\" xmlns:xenc=\"{XmlEncryptionNamespace}\">" +
                "<xenc:EncryptedKey><xenc:CipherData><xenc:CipherValue>value</xenc:CipherValue>" +
                "</xenc:CipherData></xenc:EncryptedKey></wst:RequestedProofToken>";
            var context = new WsSerializationContext(WsTrustVersion.Trust13);
            RequestedProofToken proofToken;
            using (XmlDictionaryReader reader = CreateReader(xml))
                proofToken = WsTrustSerializer.ReadRequestedProofToken(reader, context);

            Assert.NotNull(proofToken.EncryptedKey);

            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
            WsTrustSerializer.WriteRequestedProofToken(writer, context, proofToken);
            writer.Flush();

            var document = new XmlDocument { XmlResolver = null };
            document.LoadXml(Encoding.UTF8.GetString(stream.ToArray()));
            XmlNode encryptedKey = document.DocumentElement.FirstChild;
            Assert.Equal("EncryptedKey", encryptedKey.LocalName);
            Assert.Equal(XmlEncryptionNamespace, encryptedKey.NamespaceURI);
            Assert.Equal("value", encryptedKey.InnerText);
        }

        [Fact]
        public void RequestedProofToken_EmptyEncryptedKey_FailsBeforeWriting()
        {
            var context = new WsSerializationContext(WsTrustVersion.Trust13);
            var proofToken = new RequestedProofToken(new EncryptedKey());
            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);

            XmlWriteException exception = Assert.Throws<XmlWriteException>(
                () => WsTrustSerializer.WriteRequestedProofToken(writer, context, proofToken));

            Assert.StartsWith("IDX15408:", exception.Message, StringComparison.Ordinal);
            writer.Flush();
            Assert.Empty(stream.ToArray());
        }

        [Fact]
        public void Entropy_ProtectedKey_FailsBeforeWriting()
        {
            var context = new WsSerializationContext(WsTrustVersion.Trust13);
            var entropy = new Entropy(
                new ProtectedKey(Guid.NewGuid().ToByteArray(), Default.SymmetricEncryptingCredentials));
            using var stream = new MemoryStream();
            using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);

            XmlWriteException exception = Assert.Throws<XmlWriteException>(
                () => WsTrustSerializer.WriteEntropy(writer, context, entropy));

            Assert.StartsWith("IDX15408:", exception.Message, StringComparison.Ordinal);
            writer.Flush();
            Assert.Empty(stream.ToArray());
        }

        private static XmlDictionaryReader CreateReader(string xml)
        {
            return XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(xml), XmlDictionaryReaderQuotas.Max);
        }
    }
}
