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
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

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
            //  if this clas becomes public, we will need to check parameters
            //  XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.AppliesTo, @namespace);

            // brentsch - TODO, TESTCASE
            if (reader.IsEmptyElement)
            {
                reader.Skip();
                return new AppliesTo();
            }

            reader.ReadStartElement();
            var appliesTo = new AppliesTo { EndpointReference = _wsAddressingSerializer.ReadEndpointReference(reader) };
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
            //  if this clas becomes public, we will need to check parameters
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

        public void WriteAppliesTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AppliesTo appliesTo)
        {
            //  if this clas becomes public, we will need to check parameters
            //  WsUtils.ValidateParamsForWritting(writer, serializationContext, appliesTo, nameof(appliesTo));

            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.AppliesTo, serializationContext.PolicyConstants.Namespace);
            if (appliesTo.EndpointReference != null)
                _wsAddressingSerializer.WriteEndpointReference(writer, serializationContext, appliesTo.EndpointReference);

            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="policyReference"></param>
        public void WritePolicyReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, PolicyReference policyReference)
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