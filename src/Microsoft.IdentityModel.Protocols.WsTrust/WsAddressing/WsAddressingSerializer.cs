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

using System;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

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
            XmlUtil.CheckReaderOnEntry(reader, WsAddressingElements.EndpointReference);
            foreach (var @namespace in WsAddressingConstants.KnownNamespaces)
            {
                if (reader.IsNamespaceUri(@namespace))
                {
                    bool isEmptyElement = reader.IsEmptyElement;
                    reader.ReadStartElement();
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while (reader.IsStartElement())
                    {
                        bool isInnerEmptyElement = reader.IsEmptyElement;
                        var subtreeReader = reader.ReadSubtree();
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

            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(WsTrust.LogMessages.IDX15002, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing200408.Namespace, WsAddressingConstants.Addressing10.Namespace, reader.NamespaceURI)));
        }

        public void WriteEndpointReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, EndpointReference endpointReference)
        {
            WsUtils.ValidateParamsForWritting(writer, serializationContext, endpointReference, nameof(endpointReference));
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.EndpointReference, serializationContext.AddressingConstants.Namespace);
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.Address, serializationContext.AddressingConstants.Namespace);
            writer.WriteString(endpointReference.Uri.AbsoluteUri);
            writer.WriteEndElement();
            foreach (XmlElement element in endpointReference.AdditionalXmlElements)
                element.WriteTo(writer);

            writer.WriteEndElement();
        }
    }
}