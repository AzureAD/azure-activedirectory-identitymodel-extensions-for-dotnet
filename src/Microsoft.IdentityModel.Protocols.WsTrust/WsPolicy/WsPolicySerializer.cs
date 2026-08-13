// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Policy.
    /// </summary>
    internal class WsPolicySerializer
    {
        private WsAddressingSerializer _wsAddressingSerializer = new WsAddressingSerializer();

        public WsPolicySerializer()
        {
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <param name="namespace"></param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual AppliesTo ReadAppliesTo(XmlDictionaryReader reader, string @namespace)
        {
            if (reader.IsEmptyElement)
            {
                WsUtils.SkipElement(reader);
                return new AppliesTo();
            }

            reader.ReadStartElement();
            var appliesTo = new AppliesTo(_wsAddressingSerializer.ReadEndpointReference(reader));
            reader.ReadEndElement();

            return appliesTo;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="namespace"></param>
        public virtual PolicyReference ReadPolicyReference(XmlDictionaryReader reader, string @namespace)
        {
            //  if this class becomes public, we will need to check parameters
            //  XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.PolicyReference, @namespace);

            bool isEmptyElement = reader.IsEmptyElement;
            var attributes = XmlAttributeHolder.ReadAttributes(reader);
            var uri = XmlAttributeHolder.GetAttribute(attributes, WsPolicyAttributes.URI, @namespace);
            var digest = XmlAttributeHolder.GetAttribute(attributes, WsPolicyAttributes.Digest, @namespace);
            var digestAlgorithm = XmlAttributeHolder.GetAttribute(attributes, WsPolicyAttributes.DigestAlgorithm, @namespace);
            reader.ReadStartElement();
            reader.MoveToContent();

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new PolicyReference(uri, digest, digestAlgorithm);
        }

        public static void WriteAppliesTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AppliesTo appliesTo)
        {
            //  if this clas becomes public, we will need to check parameters
            //  WsUtils.ValidateParamsForWritting(writer, serializationContext, appliesTo, nameof(appliesTo));

            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.AppliesTo, serializationContext.PolicyConstants.Namespace);
            if (appliesTo.EndpointReference != null)
                WsAddressingSerializer.WriteEndpointReference(writer, serializationContext, appliesTo.EndpointReference);

            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="policyReference"></param>
        public static void WritePolicyReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, PolicyReference policyReference)
        {
            //  if this clas becomes public, we will need to check parameters
            //  WsUtils.ValidateParamsForWritting(writer, serializationContext, policyReference, nameof(policyReference));

            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.PolicyReference, serializationContext.PolicyConstants.Namespace);
            if (!string.IsNullOrEmpty(policyReference.Uri))
                writer.WriteAttributeString(WsPolicyAttributes.URI, policyReference.Uri);

            if (!string.IsNullOrEmpty(policyReference.Digest))
                writer.WriteAttributeString(WsPolicyAttributes.Digest, policyReference.Digest);

            if (!string.IsNullOrEmpty(policyReference.DigestAlgorithm))
                writer.WriteAttributeString(WsPolicyAttributes.DigestAlgorithm, policyReference.DigestAlgorithm);

            writer.WriteEndElement();
        }
    }
}
