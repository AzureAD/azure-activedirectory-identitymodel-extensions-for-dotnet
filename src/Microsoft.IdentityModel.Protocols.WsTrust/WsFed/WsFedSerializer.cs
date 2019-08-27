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
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Xml;


#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Federation.
    /// </summary>
    internal class WsFedSerializer
    {
        public WsFedSerializer()
        {
            //  if this clas becomes public, we will need to check parameters on public methods
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual AdditionalContext ReadAdditionalContext(XmlDictionaryReader reader, string @namespace)
        {
            //  <auth:AdditionalContext>
            //    <auth:ContextItem Name="xs:anyURI" Scope="xs:anyURI" ? ...>
            //      (<auth:Value>xs:string</auth:Value> |
            //       xs:any ) ?
            //    </auth:ContextItem> *
            //    ...
            //  </auth:AdditionalContext>

            var additionalContext = new AdditionalContext();
            var isEmptyElement = reader.IsEmptyElement;

            // brentsch - TODO, this is an open spec, we are skipping all unknown attributes.
            reader.ReadStartElement();
            try
            {
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(WsFedElements.ContextItem, @namespace))
                    {
                        additionalContext.Items.Add(ReadContextItem(reader, @namespace));
                    }
                    else
                    {
                        reader.Skip();
                    }
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30016, WsFedElements.ContextItem), ex));
            }

            // </AdditionalContext>
            if (!isEmptyElement)
                reader.ReadEndElement();

            return additionalContext;
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual ContextItem ReadContextItem(XmlDictionaryReader reader, string @namespace)
        {
            //    <auth:ContextItem Name="xs:anyURI" Scope="xs:anyURI" ? ...>
            //      (<auth:Value>xs:string</auth:Value> |
            //       xs:any ) ?
            //    </auth:ContextItem> *

            var isEmptyElement = reader.IsEmptyElement;
            var attributes = XmlAttributeHolder.ReadAttributes(reader);
            var name = XmlAttributeHolder.GetAttribute(attributes, WsFedAttributes.Name, @namespace);
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

            var contextItem = new ContextItem(name)
            {
                Scope = XmlAttributeHolder.GetAttribute(attributes, WsFedAttributes.Scope, @namespace)
            };

            reader.ReadStartElement();
            if (reader.IsStartElement(WsFedElements.Value, @namespace))
            {
                var value = XmlUtil.ReadStringElement(reader);
                if (!string.IsNullOrEmpty(value))
                    contextItem.Value = value;
            }
            else
                reader.Skip();

            // </ContextItem>
            if (!isEmptyElement)
                reader.ReadEndElement();

            return contextItem;
        }

        /// <summary>
        /// Creates and populates a <see cref="ClaimType"/> by reading xml.
        /// Expects the <see cref="XmlDictionaryReader"/> to be positioned on the StartElement: "ClaimType" in the namespace passed in.
        /// </summary>
        /// <param name="reader">a <see cref="XmlDictionaryReader"/> positioned at the StartElement: "ClaimType".</param>
        /// <param name="namespace">the namespace for the StartElement.</param>
        /// <returns>a populated <see cref="ClaimType"/>.</returns>
        /// <remarks>Checking for the correct StartElement is as follows.</remarks>
        /// <remarks>if @namespace is null, then <see cref="XmlDictionaryReader.IsLocalName(string)"/> will be called.</remarks>
        /// <remarks>if @namespace is not null or empty, then <see cref="XmlDictionaryReader.IsStartElement(XmlDictionaryString, XmlDictionaryString)"/> will be called.></remarks>
        /// <exception cref="ArgumentNullException">if reader is null.</exception>
        /// <exception cref="XmlReadException">if reader is not positioned on a StartElement.</exception>
        /// <exception cref="XmlReadException">if the StartElement does not match the expectations in remarks.</exception>
        public virtual ClaimType ReadClaimType(XmlDictionaryReader reader, string @namespace)
        {
            // <auth:ClaimType 
            //      Uri="a14bf1a3-a189-4a81-9d9a-7d3dfeb7724a"
            //      Optional="true/false">
            //   <auth:Value>
            //      77a6fa04-0454-4d08-8761-2a840e281399
            //   </auth:Value>
            // </auth:ClaimType>

            var attributes = XmlAttributeHolder.ReadAttributes(reader);
            var uri = XmlAttributeHolder.GetAttribute(attributes, WsFedAttributes.Uri, @namespace);
            if (string.IsNullOrEmpty(uri))
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

            var optionalAttribute = XmlAttributeHolder.GetAttribute(attributes, WsFedAttributes.Optional, @namespace);
            bool? optional = null;
            if (!string.IsNullOrEmpty(optionalAttribute))
                optional = XmlConvert.ToBoolean(optionalAttribute);

            string value = null;
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            reader.MoveToContent();

            // brentsch - TODO, need loop for multiple elements
            if (reader.IsStartElement(WsFedElements.Value, @namespace))
                value = XmlUtil.ReadStringElement(reader);

            if (!isEmptyElement)
                reader.ReadEndElement();

            // brentsch - TODO, TESTCASE
            if (optional.HasValue && !string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, IsOptional = optional, Value = value };
            else if (optional.HasValue)
                return new ClaimType { Uri = uri, IsOptional = optional };
            else if (!string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, Value = value };

            return new ClaimType { Uri = uri };
        }

        public void WriteClaimType(XmlDictionaryWriter writer, WsSerializationContext serializationContext, ClaimType claimType)
        {
            writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ClaimType, serializationContext.FedConstants.AuthNamespace);
            writer.WriteAttributeString(WsFedAttributes.Uri, claimType.Uri);
            if (claimType.IsOptional.HasValue)
                writer.WriteAttributeString(WsFedAttributes.Optional, XmlConvert.ToString(claimType.IsOptional.Value));

            writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, claimType.Value);
            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="additionalContext"></param>
        public void WriteAdditionalContext(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AdditionalContext additionalContext)
        {
            //  <auth:AdditionalContext>
            //    <auth:ContextItem Name="xs:anyURI" Scope="xs:anyURI" ? ...>
            //      (<auth:Value>xs:string</auth:Value> |
            //       xs:any ) ?
            //    </auth:ContextItem> *
            //    ...
            //  </auth:AdditionalContext>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, additionalContext, nameof(additionalContext));
            writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.AdditionalContext, serializationContext.FedConstants.AuthNamespace);
            foreach (var contextItem in additionalContext.Items)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ContextItem, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Name, contextItem.Name);
                if (contextItem.Scope != null)
                    writer.WriteAttributeString(WsFedAttributes.Scope, contextItem.Scope);

                if (!string.IsNullOrEmpty(contextItem.Value))
                    writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, contextItem.Value);

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }
    }
}