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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Security.
    /// </summary>
    public static class WsSecuritySerializer
    {
        public static XmlElement GetXmlElement(SecurityTokenReference securityTokenReference, WsSerializationContext wsSerializationContext)
        {
            if (securityTokenReference == null)
                throw LogHelper.LogArgumentNullException(nameof(securityTokenReference));

            if (wsSerializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(wsSerializationContext));

            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    WsSecuritySerializer.WriteSecurityTokenReference(writer, wsSerializationContext, securityTokenReference);
                    writer.Flush();
                    stream.Seek(0, SeekOrigin.Begin);
                    var dom = new XmlDocument
                    {
                        PreserveWhitespace = true
                    };

                    using (var textReader = new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit })
                    {
                        dom.Load(textReader);
                        return dom.DocumentElement;
                    }
                }
            }
        }

        internal static XmlElement GetXmlElement (SecurityTokenReference securityTokenReference, WsTrustVersion wsTrustVersion)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    WriteSecurityTokenReference(writer, new WsSerializationContext(wsTrustVersion), securityTokenReference);
                    writer.Flush();
                    stream.Seek(0, SeekOrigin.Begin);
                    var dom = new XmlDocument
                    {
                        PreserveWhitespace = true
                    };

                    using (var textReader = new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit })
                    {
                        dom.Load(textReader);
                        return dom.DocumentElement;
                    }
                }
            }
        }

        internal static SecurityTokenReference ReadSecurityTokenReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <wsse:SecurityTokenReference wsu:Id="...",
            //                               wsse11:TokenType="...",
            //                               wsse:Usage="...">
            //      ...
            //  </wsse:SecurityTokenReference>

            XmlAttributeHolder[] xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
            var securityTokenReference = new SecurityTokenReference
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace),
                Usage = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Usage, WsSecurityConstants.WsSecurity10.Namespace)
            };
            
            // The TokenType attribute is part of the Ws-Security 1.1 spec.
            if (serializationContext.SecurityVersion == WsSecurityVersion.Security11)
                securityTokenReference.TokenType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace);

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            if (reader.IsStartElement() && reader.IsLocalName(WsSecurityElements.KeyIdentifier))
                securityTokenReference.KeyIdentifier = ReadKeyIdentifier(reader);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return securityTokenReference;
        }

        internal static KeyIdentifier ReadKeyIdentifier(XmlDictionaryReader reader)
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
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace),
                EncodingType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.EncodingType, WsSecurityConstants.WsSecurity10.Namespace),
                ValueType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.ValueType, WsSecurityConstants.WsSecurity10.Namespace)
            };

            reader.ReadStartElement();
            if (!isEmptyElement)
            {
                keyIdentifier.Value = reader.ReadContentAsString();
                reader.ReadEndElement();
            }

            return keyIdentifier;
        }

        internal static void WriteKeyIdentifier(XmlDictionaryWriter writer, KeyIdentifier keyIdentifier)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            var wsse = writer.LookupPrefix(WsSecurityConstants.WsSecurity10.Namespace) ?? WsSecurityConstants.WsSecurity10.Prefix;
            var wsu = writer.LookupPrefix(WsUtilityConstants.WsUtility10.Namespace) ?? WsUtilityConstants.WsUtility10.Prefix;

            writer.WriteStartElement(wsse, WsSecurityElements.KeyIdentifier, WsSecurityConstants.WsSecurity10.Namespace);

            if (!string.IsNullOrEmpty(keyIdentifier.Id))
                writer.WriteAttributeString(wsu, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace, keyIdentifier.Id);

            if (!string.IsNullOrEmpty(keyIdentifier.ValueType))
                writer.WriteAttributeString(WsSecurityAttributes.ValueType, keyIdentifier.ValueType);

            if (!string.IsNullOrEmpty(keyIdentifier.EncodingType))
                writer.WriteAttributeString(WsSecurityAttributes.EncodingType, keyIdentifier.EncodingType);

            if (!string.IsNullOrEmpty(keyIdentifier.Value))
                writer.WriteString(keyIdentifier.Value);

            writer.WriteEndElement();
        }

        internal static void WriteSecurityTokenReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            // <wsse:SecurityTokenReference wsu:Id="..."
            //                              wsse11:TokenType="..."
            //                              wsse:Usage="...">
            //     ...
            // </wsse:SecurityTokenReference>

            var wsse = writer.LookupPrefix(WsSecurityConstants.WsSecurity10.Namespace) ?? WsSecurityConstants.WsSecurity10.Prefix;
            var wsse11 = writer.LookupPrefix(WsSecurityConstants.WsSecurity11.Namespace) ?? WsSecurityConstants.WsSecurity11.Prefix;
            var wsu = writer.LookupPrefix(WsUtilityConstants.WsUtility10.Namespace) ?? WsUtilityConstants.WsUtility10.Prefix;

            writer.WriteStartElement(wsse, WsSecurityElements.SecurityTokenReference, serializationContext.SecurityConstants.Namespace);

            // The TokenType attribute is described in the Ws-Security 1.1 specification.
            if (serializationContext.SecurityVersion == WsSecurityVersion.Security11)
                writer.WriteAttributeString(wsse11, WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace, securityTokenReference.TokenType);

            if (!string.IsNullOrEmpty(securityTokenReference.Id))
                writer.WriteAttributeString(wsu, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace, securityTokenReference.Id);

            if (!string.IsNullOrEmpty(securityTokenReference.Usage))
                writer.WriteAttributeString(wsse, WsSecurityAttributes.Usage, WsSecurityConstants.WsSecurity10.Namespace, securityTokenReference.Usage);

            if (securityTokenReference.KeyIdentifier != null)
                WriteKeyIdentifier(writer, securityTokenReference.KeyIdentifier);

            writer.WriteEndElement();
        }
    }
}
