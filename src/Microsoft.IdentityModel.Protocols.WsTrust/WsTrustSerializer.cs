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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Reads and writes WS-Trust requests and responses.
    /// </summary>
    public class WsTrustSerializer
    {
        private readonly WsSecuritySerializer _wsSecuritySerializer = new WsSecuritySerializer();
        private readonly WsFedSerializer _wsFedSerializer = new WsFedSerializer();
        private readonly WsPolicySerializer _wsPolicySerializer = new WsPolicySerializer();

        internal const string GeneratedDateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffffZ";

        public WsTrustSerializer()
        {
            SecurityTokenHandlers = new Collection<SecurityTokenHandler>
            {
                new SamlSecurityTokenHandler(),
                new Saml2SecurityTokenHandler()
            };
        }

        public BinarySecret ReadBinarySecrect(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:BinarySecret Type="...">
            //      ...
            //  </t:BinarySecret>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.BinarySecret, serializationContext);
            try
            {
                var binarySecret = new BinarySecret();
                if (!reader.IsEmptyElement)
                {
                    XmlAttributeHolder[] attributes = XmlAttributeHolder.ReadAttributes(reader);
                    string encodingType = XmlAttributeHolder.GetAttribute(attributes, WsTrustAttributes.Type, serializationContext.TrustConstants.Namespace);
                    if (!string.IsNullOrEmpty(encodingType))
                        binarySecret.EncodingType = encodingType;

                    reader.ReadStartElement();
                    byte[] data = reader.ReadContentAsBase64();
                    if (data != null)
                        binarySecret.Data = data;

                    reader.ReadEndElement();
                }

                return binarySecret;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        public virtual Claims ReadClaims(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            // <trust:Claims
            //  Dialect="edef1723d88b4897a8792d2fc62f9148">
            //      <auth:ClaimType
            //            Uri="a14bf1a3a1894a819d9a7d3dfeb7724a">
            //          <auth:Value>
            //              77a6fa0404544d0887612a840e281399
            //          </auth:Value>
            //      </auth:ClaimType>
            // </trust:Claims>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.Claims, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                XmlAttributeHolder[] attributes = XmlAttributeHolder.ReadAttributes(reader);

                string dialect = XmlAttributeHolder.GetAttribute(attributes, WsTrustAttributes.Dialect, serializationContext.TrustConstants.Namespace);
                reader.ReadStartElement();
                var claimTypes = new List<ClaimType>();
                while (reader.IsStartElement())
                {
                    if (reader.IsLocalName(WsFedElements.ClaimType))
                    {
                        claimTypes.Add(_wsFedSerializer.ReadClaimType(reader, serializationContext.FedConstants.AuthNamespace));
                    }
                    else
                    {
                        reader.Skip();
                    }
                }

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return new Claims(dialect, claimTypes);
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        public Entropy ReadEntropy(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:Entropy>
            //      <t:BinarySecret>
            //          ...
            //      </t:BinarySecret>
            //  </t:Entropy>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.Entropy, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;

                reader.ReadStartElement();
                var entropy = new Entropy();
                if (reader.IsStartElement(WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace))
                    entropy.BinarySecret = ReadBinarySecrect(reader, serializationContext);

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return entropy;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.Entropy, ex);
            }
        }

        public Lifetime ReadLifetime(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:Lifetime>
            //      <wsu:Created xmlns:wsu="...">2017-04-23T16:11:17.348Z</wsu:Created>
            //      <wsu:Expires xmlns:wsu="...">2017-04-23T17:11:17.348Z</wsu:Expires>
            //  </t:Lifetime>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.Lifetime, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                reader.ReadStartElement();
                var lifetime = new Lifetime(null, null);

                if (reader.IsStartElement() && reader.IsLocalName(WsUtilityElements.Created))
                    lifetime.Created = XmlConvert.ToDateTime(XmlUtil.ReadStringElement(reader), XmlDateTimeSerializationMode.Utc);

                if (reader.IsStartElement() && reader.IsLocalName(WsUtilityElements.Expires))
                    lifetime.Expires = XmlConvert.ToDateTime(XmlUtil.ReadStringElement(reader), XmlDateTimeSerializationMode.Utc);

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return lifetime;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.Lifetime, ex);
            }
        }

        public virtual SecurityTokenElement ReadOnBehalfOf(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:OnBehalfOf>
            //      one of
            //      <wsse:SecurityTokenReference>
            //      <wsa:EndpointReference>
            //      <SecurityToken>
            //  </t:OnBehalfOf>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.OnBehalfOf, serializationContext);

            try
            {
                reader.MoveToContent();
                bool isEmptyElement = reader.IsEmptyElement;
                reader.ReadStartElement();
                foreach (SecurityTokenHandler tokenHandler in SecurityTokenHandlers)
                {
                    if (tokenHandler.CanReadToken(reader))
                    {
                        SecurityToken token = tokenHandler.ReadToken(reader);
                        if (!isEmptyElement)
                            reader.ReadEndElement();

                        return new SecurityTokenElement(token);
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.OnBehalfOf, ex);
            }

            throw XmlUtil.LogReadException(LogMessages.IDX15101, reader.ReadOuterXml());
        }

        private SecurityTokenReference ReadReference(XmlDictionaryReader reader, WsSerializationContext serializationContext, string elementName)
        {
            //  <wsse:SecurityTokenReference ...>
            //      ...
            //  </wsse:SecurityTokenReference ...>

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                reader.ReadStartElement();
                SecurityTokenReference tokenReference = _wsSecuritySerializer.ReadSecurityTokenReference(reader, serializationContext);

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return tokenReference;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, elementName, ex);
            }
        }

        public WsTrustRequest ReadRequest(XmlDictionaryReader reader)
        {
            //  <t:RequestSecurityToken Context="..." xmlns:t="...">
            //      <t:TokenType>...</t:TokenType>
            //      <t:RequestType>...</t:RequestType>
            //      <t:SecondaryParameters>...</t:SecondaryParameters>
            //      ...
            //  </t:RequestSecurityToken>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityToken);

            WsSerializationContext serializationContext;
            if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
            else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
            else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
            else
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15000, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));


            try
            {
                bool isEmptyElement = reader.IsEmptyElement;

                XmlAttributeHolder[] xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
                var trustRequest = new WsTrustRequest(serializationContext.TrustActions.Issue);
                string context = XmlAttributeHolder.GetAttribute(xmlAttributes, WsTrustAttributes.Context, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(context))
                    trustRequest.Context = context;

                reader.MoveToContent();
                reader.ReadStartElement();
                ReadRequest(reader, trustRequest, serializationContext);
                if (!isEmptyElement)
                    reader.ReadEndElement();

                return trustRequest;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw LogHelper.LogExceptionMessage(ex);

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        private void ReadRequest(XmlDictionaryReader reader, WsTrustRequest trustRequest, WsSerializationContext serializationContext)
        {
            // brentsch - TODO, PERF - create a collection of strings assuming only single elements
            while (reader.IsStartElement())
            {
                bool processed = false;
                if (reader.IsStartElement(WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.RequestType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.OnBehalfOf = ReadOnBehalfOf(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.TokenType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeyType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeySizeInBits = XmlUtil.ReadIntElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.CanonicalizationAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptionAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.SignWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.ComputedKeyAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.UseKey, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.UseKey = ReadUseKey(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.ProofEncryption, serializationContext.TrustConstants.Namespace))
                {
                    // TODO Read proof encryption key
                    reader.Read();
                }
                else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                {
                    foreach (string @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AppliesTo = _wsPolicySerializer.ReadAppliesTo(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                    {
                        ReadUnknownElement(reader, trustRequest);
                    }
                }
                else if (reader.IsLocalName(WsFedElements.AdditionalContext))
                {
                    foreach (string @namespace in WsFedConstants.KnownAuthNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AdditionalContext = _wsFedSerializer.ReadAdditionalContext(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                    {
                        ReadUnknownElement(reader, trustRequest);
                    }
                }
                else if (reader.IsStartElement(WsTrustElements.Claims, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.Claims = ReadClaims(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.PolicyReference))
                {
                    trustRequest.PolicyReference = _wsPolicySerializer.ReadPolicyReference(reader, serializationContext.PolicyConstants.Namespace);
                }
                else
                {
                    ReadUnknownElement(reader, trustRequest);
                }
            }
        }

        public RequestSecurityTokenResponse ReadRequestSeurityTokenResponse(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityTokenResponse, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                var tokenResponse = new RequestSecurityTokenResponse();
                bool processed = false;
                reader.ReadStartElement();
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.TokenType = XmlUtil.ReadStringElement(reader);
                    }
                    else if (reader.IsStartElement(WsTrustElements.Lifetime, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.Lifetime = ReadLifetime(reader, serializationContext);
                    }
                    else if (reader.IsStartElement(WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.KeyType = XmlUtil.ReadStringElement(reader);
                    }
                    else if (reader.IsStartElement(WsTrustElements.RequestedSecurityToken, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.RequestedSecurityToken = ReadRequestedSecurityToken(reader, serializationContext);
                    }
                    else if (reader.IsStartElement(WsTrustElements.RequestedAttachedReference, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.AttachedReference = ReadRequestedAttachedReference(reader, serializationContext);
                    }
                    else if (reader.IsStartElement(WsTrustElements.RequestedUnattachedReference, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.UnattachedReference = ReadRequestedUnattachedReference(reader, serializationContext);
                    }
                    else if (reader.IsStartElement(WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.RequestedProofToken = ReadRequestedProofToken(reader, serializationContext);
                    }
                    else if (reader.IsStartElement(WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace))
                    {
                        tokenResponse.Entropy = ReadEntropy(reader, serializationContext);
                    }
                    else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                    {
                        foreach (string @namespace in WsPolicyConstants.KnownNamespaces)
                        {
                            if (reader.IsNamespaceUri(@namespace))
                            {
                                tokenResponse.AppliesTo = _wsPolicySerializer.ReadAppliesTo(reader, @namespace);
                                processed = true;
                                break;
                            }
                        }

                        if (!processed)
                            reader.Skip();
                    }
                    else
                    {
                        reader.Skip();
                    }
                }

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return tokenResponse;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw LogHelper.LogExceptionMessage(ex);

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        public SecurityTokenReference ReadRequestedAttachedReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:RequestedAttachedReference>
            //      <wsse:SecurityTokenReference ...>
            //          ...
            //      </wsse:SecurityTokenReference ...>
            //  </t:RequestedAttachedReference>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.RequestedAttachedReference, serializationContext);

            try
            {
                return ReadReference(reader, serializationContext, WsTrustElements.RequestedAttachedReference);
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.RequestedAttachedReference, ex);
            }
        }

        /// <summary>
        /// Reads the RequestedR
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="serializationContext"></param>
        /// <returns></returns>
        public RequestedProofToken ReadRequestedProofToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:RequestedProofToken>
            //      <t:BinarySecret>
            //          5p76ToaxZXMFm4W6fmCcFXfDPd9WgJIM
            //      </t:BinarySecret>
            //  </t:RequestedProofToken>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.RequestedProofToken, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                reader.ReadStartElement();

                // TODO, add additional scenarios for Requested proof token;
                var proofToken = new RequestedProofToken();
                if (reader.IsStartElement(WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace))
                    proofToken.BinarySecret = ReadBinarySecrect(reader, serializationContext);

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return proofToken;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw LogHelper.LogExceptionMessage(ex);

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.RequestedProofToken, ex);
            }
        }

        /// <summary>
        /// Reads the RequestedSecurityToken element and returns a <see cref="RequestedSecurityToken"/>.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <param name="reader">an <see cref="XmlDictionaryReader"/> positioned at a RequestedSecurityToken element.</param>
        /// <param name="serializationContext">a <see cref="WsSerializationContext"/> that contains information about expected namespaces.</param>
        /// <returns>A <see cref="RequestedSecurityToken"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="serializationContext"/> or <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">Thrown if reader is not positioned at a StartElement with name ReauestSecurityToken.</exception>
        /// <exception cref="XmlReadException">Thrown if an exception occurs while reading.</exception>
        public RequestedSecurityToken ReadRequestedSecurityToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:RequestedSecurityToken>
            //      <SecurityToken>
            //      <SecurityTokenReference>
            //  </t:RequestedSecurityToken>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.RequestedSecurityToken, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                bool wasTokenRead = false;
                reader.ReadStartElement();
                reader.MoveToContent();
                RequestedSecurityToken requestedSecurityToken = new RequestedSecurityToken();

                foreach (SecurityTokenHandler tokenHandler in SecurityTokenHandlers)
                {
                    // brentsch - TODO need to remember value if handler can't be found.
                    // perhaps add delegate?
                    if (tokenHandler.CanReadToken(reader))
                    {
                        requestedSecurityToken = new RequestedSecurityToken(tokenHandler.ReadToken(reader));
                        wasTokenRead = true;
                        break;
                    }
                }

                // brentsch - TODO TEST
                if (!wasTokenRead && !isEmptyElement)
                    reader.Skip();

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return requestedSecurityToken;
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.Lifetime, ex);
            }
        }

        public SecurityTokenReference ReadRequestedUnattachedReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:RequestedUnattachedReference>
            //      <wsse:SecurityTokenReference ...>
            //          ...
            //      </wsse:SecurityTokenReference ...>
            //  </t:RequestedUnattachedReference>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.RequestedUnattachedReference, serializationContext);

            try
            {
                return ReadReference(reader, serializationContext, WsTrustElements.RequestedUnattachedReference);
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.RequestedUnattachedReference, ex);
            }
        }

        public WsTrustResponse ReadResponse(XmlDictionaryReader reader)
        {
            //  <t:RequestSecurityTokenResponse Context="..." xmlns:t="...">
            //      <t:TokenType>...</t:TokenType>
            //      <t:RequestedSecurityToken>...</t:RequestedSecurityToken>
            //      ...
            //  </t:RequestSecurityTokenResponse>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityTokenResponseCollection);

            try
            {
                WsSerializationContext serializationContext;
                if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                    serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
                else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                    serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
                else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                    serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
                else
                    throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15001, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));

                return ReadResponse(reader, serializationContext);
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw LogHelper.LogExceptionMessage(ex);

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        private WsTrustResponse ReadResponse(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            bool isEmptyElement = reader.IsEmptyElement;
            bool hasRstrCollection = false;
            var response = new WsTrustResponse();
            if (reader.IsStartElement(WsTrustElements.RequestSecurityTokenResponseCollection, serializationContext.TrustConstants.Namespace))
            {
                reader.ReadStartElement();
                hasRstrCollection = true;
            }

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(WsTrustElements.RequestSecurityTokenResponse, serializationContext.TrustConstants.Namespace))
                    response.RequestSecurityTokenResponseCollection.Add(ReadRequestSeurityTokenResponse(reader, serializationContext));
                else
                    // brentsch - need to put these elements in array
                    reader.Skip();
            }

            if (!isEmptyElement && hasRstrCollection)
                reader.ReadEndElement();

            return response;
        }

        /// <summary>
        /// TODO - We need a pluggable model here so users can plug in for custom elements.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="trustRequest"></param>
        private void ReadUnknownElement(XmlDictionaryReader reader, WsTrustRequest trustRequest)
        {
            bool isEmptyElement = reader.IsEmptyElement;
            var doc = new XmlDocument();
            doc.Load(reader.ReadSubtree());
            trustRequest.AdditionalXmlElements.Add(doc.DocumentElement);

            if (isEmptyElement)
            {
                // ReadSubTree will advance the reader to the current element's end element. If the reader is at
                // an empty element, it won't advance and the deserializer will be stuck on the empty unknown element.
                reader.Read();
            }
        }

        public UseKey ReadUseKey(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:UseKey Sig="...">
            //      SecurityTokenReference / SecurityToken
            //  </t:UseKey>

            WsUtils.CheckReaderOnEntry(reader, WsTrustElements.UseKey, serializationContext);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                XmlAttributeHolder[] attributes = XmlAttributeHolder.ReadAttributes(reader);
                string signatureId = XmlAttributeHolder.GetAttribute(attributes, WsTrustAttributes.Sig, serializationContext.TrustConstants.Namespace);

                reader.ReadStartElement();
                UseKey useKey = null;

                if (reader.IsStartElement() && reader.IsLocalName(WsSecurityElements.SecurityTokenReference))
                    useKey = new UseKey(new SecurityTokenElement(_wsSecuritySerializer.ReadSecurityTokenReference(reader, serializationContext)));

                if (!string.IsNullOrEmpty(signatureId))
                    useKey.SignatureId = signatureId;

                if (!isEmptyElement)
                    reader.ReadEndElement();

                return useKey;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw LogHelper.LogExceptionMessage(ex);

                throw XmlUtil.LogReadException(Xml.LogMessages.IDX30017, ex, WsTrustElements.RequestedProofToken, ex);
            }
        }

        public ICollection<SecurityTokenHandler> SecurityTokenHandlers { get; private set; }

        public void WriteBinarySecret(XmlDictionaryWriter writer, WsSerializationContext serializationContext, BinarySecret binarySecret)
        {
            //  <t:BinarySecret Type="...">
            //      ...
            //  </t:BinarySecret>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, binarySecret, nameof(binarySecret));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(binarySecret.EncodingType))
                    writer.WriteAttributeString(WsTrustAttributes.Type, serializationContext.TrustConstants.Namespace, binarySecret.EncodingType);

                writer.WriteBase64(binarySecret.Data, 0, binarySecret.Data.Length);
                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.BinarySecret, ex);
            }
        }

        public void WriteClaims(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Claims claims)
        {
            //  <t:Claims Dialect="...">
            //    ...
            //  </t:Claims>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, claims, nameof(claims));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Claims, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(claims.Dialect))
                    writer.WriteAttributeString(WsTrustAttributes.Dialect, claims.Dialect);

                foreach (ClaimType claimType in claims.ClaimTypes)
                    _wsFedSerializer.WriteClaimType(writer, serializationContext, claimType);

                writer.WriteEndElement();
            }
            catch(Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.Claims, ex);
            }
        }

        public void WriteEntropy(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Entropy entropy)
        {
            //  <t:Entropy>
            //      <t:BinarySecret>
            //          ...
            //      </t:BinarySecret>
            //  </t:Entropy>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, entropy, nameof(entropy));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace);
                if (entropy.BinarySecret != null)
                    WriteBinarySecret(writer, serializationContext, entropy.BinarySecret);

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.Entropy, ex);
            }
        }

        public void WriteLifetime(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Lifetime lifetime)
        {
            //  <t:Lifetime>
            //      <wsu:Created xmlns:wsu="...">2017-04-23T16:11:17.348Z</wsu:Created>
            //      <wsu:Expires xmlns:wsu="...">2017-04-23T17:11:17.348Z</wsu:Expires>
            //  </t:Lifetime>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, lifetime, nameof(lifetime));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Lifetime, serializationContext.TrustConstants.Namespace);
                if (lifetime.Created.HasValue)
                {
                    writer.WriteStartElement(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Created, WsUtilityConstants.WsUtility10.Namespace);
                    writer.WriteString(XmlConvert.ToString(lifetime.Created.Value.ToUniversalTime(), GeneratedDateTimeFormat));
                    writer.WriteEndElement();
                }

                if (lifetime.Expires.HasValue)
                {
                    writer.WriteStartElement(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Expires, WsUtilityConstants.WsUtility10.Namespace);
                    writer.WriteString(XmlConvert.ToString(lifetime.Expires.Value.ToUniversalTime(), GeneratedDateTimeFormat));
                    writer.WriteEndElement();
                }

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.Lifetime, ex);
            }
        }

        public void WriteOnBehalfOf(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenElement onBehalfOf)
        {
            //  <t:OnBehalfOf>
            //      one of
            //      <wsse:SecurityTokenReference>
            //      <wsa:EndpointReference>
            //      <SecurityToken>
            //  </t:OnBehalfOf>

            // TODO write references, etc.
            WsUtils.ValidateParamsForWritting(writer, serializationContext, onBehalfOf, nameof(onBehalfOf));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace);
                if (onBehalfOf.SecurityToken != null)
                {
                    foreach (SecurityTokenHandler tokenHandler in SecurityTokenHandlers)
                    {
                        if (tokenHandler.CanWriteSecurityToken(onBehalfOf.SecurityToken))
                        {
                            if (!tokenHandler.TryWriteSourceData(writer, onBehalfOf.SecurityToken))
                                tokenHandler.WriteToken(writer, onBehalfOf.SecurityToken);
                        }
                    }
                }

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.OnBehalfOf, ex);
            }
        }

        public void WriteProofEncryption(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenElement proofEncryption)
        {
            WsUtils.ValidateParamsForWritting(writer, serializationContext, proofEncryption, nameof(proofEncryption));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.ProofEncryption, serializationContext.TrustConstants.Namespace);

                // TODO Write proof encryption key

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.ProofEncryption, ex);
            }
        }

        public void WriteRequest(XmlDictionaryWriter writer, WsTrustVersion wsTrustVersion, WsTrustRequest trustRequest)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (wsTrustVersion == null)
                throw LogHelper.LogArgumentNullException(nameof(wsTrustVersion));

            if (trustRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(trustRequest));

            var serializationContext = new WsSerializationContext(wsTrustVersion);

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityToken, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(trustRequest.Context))
                    writer.WriteAttributeString(WsTrustAttributes.Context, trustRequest.Context);

                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace, trustRequest.RequestType);

                if (!string.IsNullOrEmpty(trustRequest.TokenType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace, trustRequest.TokenType);

                if (!string.IsNullOrEmpty(trustRequest.KeyType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, trustRequest.KeyType);

                if (trustRequest.KeySizeInBits.HasValue)
                {
                    writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace);
                    writer.WriteValue(trustRequest.KeySizeInBits.Value);
                    writer.WriteEndElement();
                }

                if (!string.IsNullOrEmpty(trustRequest.CanonicalizationAlgorithm))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.CanonicalizationAlgorithm);

                if (!string.IsNullOrEmpty(trustRequest.EncryptionAlgorithm))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.EncryptionAlgorithm);

                if (!string.IsNullOrEmpty(trustRequest.EncryptWith))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace, trustRequest.EncryptWith);

                if (!string.IsNullOrEmpty(trustRequest.SignWith))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace, trustRequest.SignWith);

                if (!string.IsNullOrEmpty(trustRequest.ComputedKeyAlgorithm))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.ComputedKeyAlgorithm);

                if (trustRequest.AppliesTo != null)
                    _wsPolicySerializer.WriteAppliesTo(writer, serializationContext, trustRequest.AppliesTo);

                if (trustRequest.OnBehalfOf != null)
                    WriteOnBehalfOf(writer, serializationContext, trustRequest.OnBehalfOf);

                if (trustRequest.AdditionalContext != null)
                    _wsFedSerializer.WriteAdditionalContext(writer, serializationContext, trustRequest.AdditionalContext);

                if (trustRequest.Claims != null)
                    WriteClaims(writer, serializationContext, trustRequest.Claims);

                if (trustRequest.PolicyReference != null)
                    _wsPolicySerializer.WritePolicyReference(writer, serializationContext, trustRequest.PolicyReference);

                if (trustRequest.ProofEncryption != null)
                    WriteProofEncryption(writer, serializationContext, trustRequest.ProofEncryption);

                if (trustRequest.UseKey != null)
                    WriteUseKey(writer, serializationContext, trustRequest.UseKey);

                foreach (XmlElement xmlElement in trustRequest.AdditionalXmlElements)
                    xmlElement.WriteTo(writer);

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.RequestSecurityToken, ex);
            }
        }

        public void WriteRequestSecurityTokenResponse(XmlDictionaryWriter writer, WsTrustVersion wsTrustVersion, RequestSecurityTokenResponse requestSecurityTokenResponse)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (wsTrustVersion == null)
                throw LogHelper.LogArgumentNullException(nameof(wsTrustVersion));

            if (requestSecurityTokenResponse == null)
                throw LogHelper.LogArgumentNullException(nameof(requestSecurityTokenResponse));

            var serializationContext = new WsSerializationContext(wsTrustVersion);

            try
            {
                // <RequestSecurityTokenResponse>
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityTokenResponse, serializationContext.TrustConstants.Namespace);

                //  @Context="..."
                if (!string.IsNullOrEmpty(requestSecurityTokenResponse.Context))
                    writer.WriteAttributeString(WsTrustAttributes.Context, requestSecurityTokenResponse.Context);

                //  <Lifetime>
                if (requestSecurityTokenResponse.Lifetime != null)
                    WriteLifetime(writer, serializationContext, requestSecurityTokenResponse.Lifetime);

                //  <TokenType>
                if (!string.IsNullOrEmpty(requestSecurityTokenResponse.TokenType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace, requestSecurityTokenResponse.TokenType);

                //  <RequestedSecurityToken>
                if (requestSecurityTokenResponse.RequestedSecurityToken != null)
                    WriteRequestedSecurityToken(writer, serializationContext, requestSecurityTokenResponse.RequestedSecurityToken);

                // <KeyType>
                if (!string.IsNullOrEmpty(requestSecurityTokenResponse.KeyType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, requestSecurityTokenResponse.KeyType);

                // <AppliesTo>
                if (requestSecurityTokenResponse.AppliesTo != null)
                    _wsPolicySerializer.WriteAppliesTo(writer, serializationContext, requestSecurityTokenResponse.AppliesTo);

                // <Entropy>
                if (requestSecurityTokenResponse.Entropy != null)
                    WriteEntropy(writer, serializationContext, requestSecurityTokenResponse.Entropy);

                // <RequestedProofToken>
                if (requestSecurityTokenResponse.RequestedProofToken != null)
                    WriteRequestedProofToken(writer, serializationContext, requestSecurityTokenResponse.RequestedProofToken);

                // <RequestedAttachedReference>
                if (requestSecurityTokenResponse.AttachedReference != null)
                    WriteRequestedAttachedReference(writer, serializationContext, requestSecurityTokenResponse.AttachedReference);

                // <RequestedUnattachedReference>
                if (requestSecurityTokenResponse.UnattachedReference != null)
                    WriteRequestedUnattachedReference(writer, serializationContext, requestSecurityTokenResponse.UnattachedReference);

                // </RequestSecurityTokenResponse>
                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.RequestSecurityToken, ex);
            }
        }

        public void WriteRequestedAttachedReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            //  <t:RequestedAttachedReference>
            //      <SecurityTokenReference d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            //          <KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
            //      </SecurityTokenReference>
            //  </t:RequestedAttachedReference>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, securityTokenReference, nameof(securityTokenReference));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedAttachedReference, serializationContext.TrustConstants.Namespace);
            _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, securityTokenReference);
            writer.WriteEndElement();
        }

        public void WriteRequestedProofToken(XmlDictionaryWriter writer, WsSerializationContext serializationContext, RequestedProofToken requestedProofToken)
        {
            //  <t:RequestedProofToken>
            //      <t:BinarySecret>
            //          ...
            //      </t:BinarySecret>
            //  </t:RequestedProofToken>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, requestedProofToken, nameof(requestedProofToken));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace);
            if (requestedProofToken.BinarySecret != null)
                WriteBinarySecret(writer, serializationContext, requestedProofToken.BinarySecret);

            writer.WriteEndElement();
        }

        public void WriteRequestedSecurityToken(XmlDictionaryWriter writer, WsSerializationContext serializationContext, RequestedSecurityToken requestedSecurityToken)
        {
            //  <t:RequestedSecurityToken>
            //      <SecurityToken>
            //      <SecurityTokenReference>
            //  </t:RequestedSecurityToken>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, requestedSecurityToken, nameof(requestedSecurityToken));

            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedSecurityToken, serializationContext.TrustConstants.Namespace);
            foreach (SecurityTokenHandler tokenHandler in SecurityTokenHandlers)
            {
                if (tokenHandler.CanWriteSecurityToken(requestedSecurityToken.SecurityToken))
                {
                    if (!tokenHandler.TryWriteSourceData(writer, requestedSecurityToken.SecurityToken))
                        tokenHandler.WriteToken(writer, requestedSecurityToken.SecurityToken);

                    break;
                }
            }

            writer.WriteEndElement();
        }

        public void WriteRequestedUnattachedReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            //  <t:RequestedUnattachedReference>
            //    <SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            //        <KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
            //    </SecurityTokenReference>
            //  </t:RequestedUnattachedReference>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, securityTokenReference, nameof(securityTokenReference));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedUnattachedReference, serializationContext.TrustConstants.Namespace);
            _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, securityTokenReference);
            writer.WriteEndElement();
        }

        public void WriteResponse(XmlDictionaryWriter writer, WsTrustVersion wsTrustVersion, WsTrustResponse trustResponse)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (wsTrustVersion == null)
                throw LogHelper.LogArgumentNullException(nameof(wsTrustVersion));

            if (trustResponse == null)
                throw LogHelper.LogArgumentNullException(nameof(trustResponse));

            var serializationContext = new WsSerializationContext(wsTrustVersion);

            try
            {
                // <RequestSecurityTokenResponseCollection>
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityTokenResponseCollection, serializationContext.TrustConstants.Namespace);

                foreach (RequestSecurityTokenResponse response in trustResponse.RequestSecurityTokenResponseCollection)
                {
                    WriteRequestSecurityTokenResponse(writer, wsTrustVersion, response);
                }

                // </RequestSecurityTokenResponseCollection>
                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.RequestSecurityToken, ex);
            }
        }

        public void WriteUseKey(XmlDictionaryWriter writer, WsSerializationContext serializationContext, UseKey useKey)
        {
            //  <t:UseKey Sig="...">
            //    SecurityToken OR SecurityTokenReference
            //  </t:UseKey>

            WsUtils.ValidateParamsForWritting(writer, serializationContext, useKey, nameof(useKey));

            try
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.UseKey, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(useKey.SignatureId))
                    writer.WriteAttributeString(WsTrustAttributes.Sig, useKey.SignatureId);

                if (useKey.SecurityTokenElement.SecurityTokenReference != null)
                    _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, useKey.SecurityTokenElement.SecurityTokenReference);

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                if (ex is XmlWriteException)
                    throw;

                throw XmlUtil.LogWriteException(Xml.LogMessages.IDX30407, ex, WsTrustElements.RequestSecurityToken, ex);
            }
        }
    }
}
