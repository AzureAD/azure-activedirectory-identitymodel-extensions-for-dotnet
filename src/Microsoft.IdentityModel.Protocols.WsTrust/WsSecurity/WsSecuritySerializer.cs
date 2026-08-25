// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Security.
    /// see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf (1.1)
    /// see: http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html (1.1.1)
    /// </summary>
    public static class WsSecuritySerializer
    {
        /// <summary>
        /// Creates an <see cref="XmlElement"/> to wrap a <see cref="SecurityTokenReference"/>
        /// </summary>
        /// <param name="securityTokenReference"></param>
        /// <returns></returns>
        public static XmlElement CreateXmlElement(SecurityTokenReference securityTokenReference)
        {
            if (securityTokenReference == null)
                throw LogHelper.LogArgumentNullException(nameof(securityTokenReference));

            using (var stream = WsUtils.CreateBoundedMemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false))
                {
                    WriteSecurityTokenReference(writer, securityTokenReference);
                    writer.Flush();
                    stream.Seek(0, SeekOrigin.Begin);
                    var dom = new XmlDocument
                    {
                        PreserveWhitespace = true,
                        XmlResolver = null
                    };

                    using (var dictReader = XmlDictionaryReader.CreateTextReader(stream, WsUtils.BoundedReaderQuotas))
                    using (var depthLimitingReader = new DepthLimitingXmlReader(dictReader, WsUtils.BoundedReaderQuotas.MaxDepth))
                    {
                        dom.Load(depthLimitingReader);
                        return dom.DocumentElement;
                    }
                }
            }
        }

        internal static SecurityTokenReference ReadSecurityTokenReference(XmlDictionaryReader reader)
        {
            //  <wsse:SecurityTokenReference wsu:Id="...",
            //                               wsse:TokenType="...",
            //                               wsse:Usage="...">
            //      ...
            //  </wsse:SecurityTokenReference>

            XmlAttributeHolder[] xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
            var securityTokenReference = new SecurityTokenReference();

            string id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace);
            string tokenType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace);
            string usage = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Usage, WsSecurityConstants.WsSecurity10.Namespace);

            if (!string.IsNullOrEmpty(id))
                securityTokenReference.Id = id;

            if (!string.IsNullOrEmpty(tokenType))
                securityTokenReference.TokenType = tokenType;

            if (!string.IsNullOrEmpty(usage))
                securityTokenReference.Usage = usage;

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            int childCount = 0;
            while (reader.IsStartElement())
            {
                WsUtils.EnsureElementCount(++childCount);
                if (reader.IsStartElement(WsSecurityElements.KeyIdentifier, WsSecurityConstants.WsSecurity10.Namespace))
                    securityTokenReference.KeyIdentifier = ReadKeyIdentifier(reader);
                else
                    WsUtils.SkipElement(reader);
            }

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

            var keyIdentifier = new KeyIdentifier();
            string id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace);
            string encodingType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.EncodingType, WsSecurityConstants.WsSecurity10.Namespace);
            string valueType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.ValueType, WsSecurityConstants.WsSecurity10.Namespace);

            if (!string.IsNullOrEmpty(id))
                keyIdentifier.Id = id;

            if (!string.IsNullOrEmpty(encodingType))
                keyIdentifier.EncodingType = encodingType;

            if (!string.IsNullOrEmpty(valueType))
                keyIdentifier.ValueType = valueType;

            if (isEmptyElement)
                reader.ReadStartElement();
            else
                keyIdentifier.Value = WsUtils.ReadStringElement(reader);

            return keyIdentifier;
        }

        internal static void WriteKeyIdentifier(XmlDictionaryWriter writer, KeyIdentifier keyIdentifier)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            writer.WriteStartElement(WsSecurityConstants.WsSecurity10.Prefix, WsSecurityElements.KeyIdentifier, WsSecurityConstants.WsSecurity10.Namespace);

            if (!string.IsNullOrEmpty(keyIdentifier.Id))
                writer.WriteAttributeString(WsUtilityConstants.WsUtility10.Prefix, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace, keyIdentifier.Id);

            if (!string.IsNullOrEmpty(keyIdentifier.ValueType))
                writer.WriteAttributeString(WsSecurityAttributes.ValueType, keyIdentifier.ValueType);

            if (!string.IsNullOrEmpty(keyIdentifier.EncodingType))
                writer.WriteAttributeString(WsSecurityAttributes.EncodingType, keyIdentifier.EncodingType);

            if (!string.IsNullOrEmpty(keyIdentifier.Value))
                writer.WriteString(keyIdentifier.Value);

            writer.WriteEndElement();
        }

        internal static void WriteSecurityTokenReference(XmlDictionaryWriter writer, SecurityTokenReference securityTokenReference)
        {
            // <wsse:SecurityTokenReference>
            //      <wsse:KeyIdentifier wsu:Id="..."
            //                          ValueType="..."
            //                          EncodingType="...">
            //          ...
            //      </wsse:KeyIdentifier>
            //  </wsse:SecurityTokenReference>

            writer.WriteStartElement(WsSecurityConstants.WsSecurity10.Prefix, WsSecurityElements.SecurityTokenReference, WsSecurityConstants.WsSecurity10.Namespace);

            // For Saml2 tokens, the 'TokenType' was defined in must be in wsse1.1 namespace
            if (!string.IsNullOrEmpty(securityTokenReference.TokenType))
                writer.WriteAttributeString(WsSecurityAttributes.TokenType, WsSecurityConstants.WsSecurity11.Namespace, securityTokenReference.TokenType);

            if (!string.IsNullOrEmpty(securityTokenReference.Id))
                writer.WriteAttributeString(WsUtilityConstants.WsUtility10.Prefix, WsUtilityAttributes.Id, WsUtilityConstants.WsUtility10.Namespace, securityTokenReference.Id);

            if (!string.IsNullOrEmpty(securityTokenReference.Usage))
                writer.WriteAttributeString(WsSecurityAttributes.Usage, WsSecurityConstants.WsSecurity10.Namespace, securityTokenReference.Usage);

            if (securityTokenReference.KeyIdentifier != null)
                WriteKeyIdentifier(writer, securityTokenReference.KeyIdentifier);

            writer.WriteEndElement();
        }
    }
}
