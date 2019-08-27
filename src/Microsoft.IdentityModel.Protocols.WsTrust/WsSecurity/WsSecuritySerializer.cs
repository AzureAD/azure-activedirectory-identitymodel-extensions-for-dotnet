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

using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Security.
    /// </summary>
    internal class WsSecuritySerializer
    {
        public WsSecuritySerializer()
        {
            //  if this clas becomes public, we will need to check parameters on public methods
        }

        public static XmlElement GetXmlElement (SecurityTokenReference securityTokenReference, WsTrustVersion wsTrustVersion)
        {
            using (var stream = new MemoryStream())
            {
                var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
                var serializer = new WsSecuritySerializer();
                serializer.WriteSecurityTokenReference(writer, new WsSerializationContext(wsTrustVersion), securityTokenReference);
                writer.Flush();
                stream.Seek(0, SeekOrigin.Begin);
                var dom = new XmlDocument
                {
                    PreserveWhitespace = true
                };
                dom.Load(new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit });

                return dom.DocumentElement;
            }
        }

        public SecurityTokenReference ReadSecurityTokenReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <wsse:SecurityTokenReference wsu:Id="...",
            //                               wsse:TokenType="...",
            //                               wsse:Usage="...">
            //      ...
            //  </wsse:SecurityTokenReference>

            var xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
            var securityTokenReference = new SecurityTokenReference
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, serializationContext.SecurityConstants.Namespace),
                TokenType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.TokenType, serializationContext.SecurityConstants.Namespace),
                Usage = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Usage, serializationContext.SecurityConstants.Namespace)
            };

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            if (reader.IsStartElement() && reader.IsLocalName(WsSecurityElements.KeyIdentifier))
                securityTokenReference.KeyIdentifier = ReadKeyIdentifier(reader, serializationContext);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return securityTokenReference;
        }

        public KeyIdentifier ReadKeyIdentifier(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            bool isEmptyElement = reader.IsEmptyElement;
            var xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);

            var keyIdentifier = new KeyIdentifier
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, serializationContext.AddressingConstants.Namespace),
                EncodingType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.EncodingType, serializationContext.SecurityConstants.Namespace),
                ValueType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.ValueType, serializationContext.SecurityConstants.Namespace)
            };

            reader.ReadStartElement();
            if (!isEmptyElement)
            {
                keyIdentifier.Value = reader.ReadContentAsString();
                reader.ReadEndElement();
            }

            return keyIdentifier;
        }

        public void WriteKeyIdentifier(XmlDictionaryWriter writer, WsSerializationContext serializationContext, KeyIdentifier keyIdentifier)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            writer.WriteStartElement(serializationContext.SecurityConstants.Prefix, WsSecurityElements.KeyIdentifier, serializationContext.SecurityConstants.Namespace);

            if (!string.IsNullOrEmpty(keyIdentifier.Id))
                writer.WriteAttributeString(WsUtilityAttributes.Id, keyIdentifier.Id);

            if (!string.IsNullOrEmpty(keyIdentifier.ValueType))
                writer.WriteAttributeString(WsSecurityAttributes.ValueType, keyIdentifier.ValueType);

            if (!string.IsNullOrEmpty(keyIdentifier.EncodingType))
                writer.WriteAttributeString(WsSecurityAttributes.EncodingType, keyIdentifier.EncodingType);

            if (!string.IsNullOrEmpty(keyIdentifier.Value))
                writer.WriteString(keyIdentifier.Value);

            writer.WriteEndElement();
        }

        public void WriteSecurityTokenReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            // <wsse:SecurityTokenReference>
            //      <wsse:KeyIdentifier wsu:Id="..."
            //                          ValueType="..."
            //                          EncodingType="...">
            //          ...
            //      </wsse:KeyIdentifier>
            //  </wsse:SecurityTokenReference>

            writer.WriteStartElement(serializationContext.SecurityConstants.Prefix, WsSecurityElements.SecurityTokenReference, serializationContext.SecurityConstants.Namespace);

            if (!string.IsNullOrEmpty(securityTokenReference.TokenType))
                writer.WriteAttributeString(WsSecurityAttributes.TokenType, WsSecurity11Constants.WsSecurity11.Namespace, securityTokenReference.TokenType);

            if (!string.IsNullOrEmpty(securityTokenReference.Id))
                writer.WriteAttributeString(WsUtilityAttributes.Id, securityTokenReference.Id);

            if (securityTokenReference.KeyIdentifier != null)
                WriteKeyIdentifier(writer, serializationContext, securityTokenReference.KeyIdentifier);

            writer.WriteEndElement();
        }
    }
}
