// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Addressing.
    /// </summary>
    internal class WsAddressingSerializer
    {
        public WsAddressingSerializer()
        {
        }

        /// <summary>
        /// Reads an <see cref="EndpointReference"/>
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual EndpointReference ReadEndpointReference(XmlDictionaryReader reader)
        {
            //  <wsa:EndpointReference>
            //    <wsa:Address>xs:anyURI</wsa:Address>
            //    <wsa:ReferenceProperties>... </wsa:ReferenceProperties> ?
            //    <wsa:ReferenceParameters>... </wsa:ReferenceParameters> ?
            //    <wsa:PortType>xs:QName</wsa:PortType> ?
            //    <wsa:ServiceName PortName="xs:NCName"?>xs:QName</wsa:ServiceName> ?
            //    <wsp:Policy> ... </wsp:Policy>*
            //  </wsa:EndpointReference>

            XmlUtil.CheckReaderOnEntry(reader, WsAddressingElements.EndpointReference);
            foreach (string @namespace in WsAddressingConstants.KnownNamespaces)
            {
                if (reader.IsNamespaceUri(@namespace))
                {
                    bool isEmptyElement = reader.IsEmptyElement;
                    reader.ReadStartElement();
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while (reader.IsStartElement())
                    {
                        bool isInnerEmptyElement = reader.IsEmptyElement;
                        XmlReader subtreeReader = reader.ReadSubtree();
                        var doc = new XmlDocument
                        {
                            PreserveWhitespace = true
                        };

                        doc.Load(subtreeReader);
                        endpointReference.AdditionalXmlElements.Add(doc.DocumentElement);
                        if (!isInnerEmptyElement)
                            reader.ReadEndElement();
                    }

                    if (!isEmptyElement)
                        reader.ReadEndElement();

                    return endpointReference;
                }
            }

            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(WsTrust.LogMessages.IDX15001, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing200408.Namespace, WsAddressingConstants.Addressing10.Namespace, reader.NamespaceURI)));
        }

        public static void WriteEndpointReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, EndpointReference endpointReference)
        {
            WsUtils.ValidateParamsForWritting(writer, serializationContext, endpointReference, nameof(endpointReference));

            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.EndpointReference, serializationContext.AddressingConstants.Namespace);
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.Address, serializationContext.AddressingConstants.Namespace);
            writer.WriteString(endpointReference.Uri);
            writer.WriteEndElement();

            foreach (XmlElement element in endpointReference.AdditionalXmlElements)
                element.WriteTo(writer);

            writer.WriteEndElement();
        }
    }
}
