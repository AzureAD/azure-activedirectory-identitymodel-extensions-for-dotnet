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
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.IdentityModelEventSource;
using static Microsoft.IdentityModel.Logging.LogHelper;
using static Microsoft.IdentityModel.Protocols.WsFederation.WsFederationConstants;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Metadata serializer class for WsFed. 
    /// </summary>
    public class WsFederationMetadataSerializer
    {

        private DSigSerializer _dsigSerializer = DSigSerializer.Default;

        /// <summary>
        /// Metadata serializer for WsFed.
        /// </summary>
        public WsFederationMetadataSerializer() { }

#region Read Metadata

        /// <summary>
        /// Read metadata and create the corresponding <see cref="WsFederationConfiguration"/>.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read metadata</param>
        /// <returns><see cref="WsFederationConfiguration"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading metadata</exception>
        public WsFederationConfiguration ReadMetadata(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var envelopeReader = new EnvelopedSignatureReader(reader);

            try
            {
                var configuration = ReadEntityDescriptor(envelopeReader);
                configuration.Signature = envelopeReader.Signature;
                return configuration;
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX22800, ex, Elements.EntityDescriptor, ex);
            }
        }

        /// <summary>
        /// Read EntityDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read entity descriptor</param>
        /// <returns><see cref="WsFederationConfiguration"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading entity descriptor</exception>
        protected virtual WsFederationConfiguration ReadEntityDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            var configuration = new WsFederationConfiguration();

            // get entityID for issuer
            var issuer = reader.GetAttribute(Attributes.EntityId);
            if (string.IsNullOrEmpty(issuer))
                throw XmlUtil.LogReadException(LogMessages.IDX22801);
            configuration.Issuer = issuer;

            // <EntityDescriptor>
            reader.ReadStartElement();

            // flag for the existence of SecurityTokenSeviceType RoleDescriptor
            var hasSecurityTokenServiceTypeRoleDescriptor = false;

            while (reader.IsStartElement())
            {
                if (IsSecurityTokenServiceTypeRoleDescriptor(reader))
                {
                    hasSecurityTokenServiceTypeRoleDescriptor = true;
                    var roleDescriptor = ReadSecurityTokenServiceTypeRoleDescriptor(reader);
                    foreach(var keyInfo in roleDescriptor.KeyInfos)
                    {
                        configuration.KeyInfos.Add(keyInfo);
                        if (!string.IsNullOrEmpty(keyInfo.CertificateData))
                        {
                            var cert = new X509Certificate2(Convert.FromBase64String(keyInfo.CertificateData));
                            configuration.SigningKeys.Add(new X509SecurityKey(cert));
                        }
                    }
                    configuration.TokenEndpoint = roleDescriptor.TokenEndpoint;
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }

            // </EntityDescriptor>
            reader.ReadEndElement();

            // The metadata xml should contain a SecurityTokenServiceType RoleDescriptor
            if (!hasSecurityTokenServiceTypeRoleDescriptor)
                throw XmlUtil.LogReadException(LogMessages.IDX22804);

            return configuration;
        }

        /// <summary>
        /// Read KeyDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read key descriptor</param>
        /// <returns><see cref="KeyInfo"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading key descriptor</exception>
        protected virtual KeyInfo ReadKeyDescriptorForSigning(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.KeyDescriptor, Namespaces.MetadataNamespace);

            var use = reader.GetAttribute(Attributes.Use);
            if (string.IsNullOrEmpty(use))
                Logger.WriteWarning(LogMessages.IDX22808);
            else if (!use.Equals(keyUse.Signing))
                throw XmlUtil.LogReadException(LogMessages.IDX22809, Attributes.Use, keyUse.Signing, use);

            // <KeyDescriptor>
            reader.ReadStartElement();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
            {
                var keyInfo = _dsigSerializer.ReadKeyInfo(reader);
                // </KeyDescriptor>
                reader.ReadEndElement();
                return keyInfo;
            }
            else
            {
                throw XmlUtil.LogReadException(LogMessages.IDX22802, reader.LocalName, reader.NamespaceURI, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);
            }
        }

        /// <summary>
        /// Read RoleDescriptor element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read security token service type role descriptor</param>
        /// <returns><see cref="SecurityTokenServiceTypeRoleDescriptor"/></returns>
        /// <exception cref="XmlReadException">if error occurs when reading role descriptor</exception>
        protected virtual SecurityTokenServiceTypeRoleDescriptor ReadSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.RoleDescriptor, Namespaces.MetadataNamespace);

            if (!IsSecurityTokenServiceTypeRoleDescriptor(reader))
                throw XmlUtil.LogReadException(LogMessages.IDX22804);

            var roleDescriptor = new SecurityTokenServiceTypeRoleDescriptor();

            // <RoleDescriptorr>
            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(Elements.KeyDescriptor, Namespaces.MetadataNamespace) && reader.GetAttribute(Attributes.Use).Equals(keyUse.Signing))
                    roleDescriptor.KeyInfos.Add(ReadKeyDescriptorForSigning(reader));
                else if (reader.IsStartElement(Elements.PassiveRequestorEndpoint, Namespaces.FederationNamespace))
                    roleDescriptor.TokenEndpoint = ReadPassiveRequestorEndpoint(reader);
                else
                    reader.ReadOuterXml();
            }

            // </RoleDescriptorr>
            reader.ReadEndElement();

            if (roleDescriptor.KeyInfos.Count == 0)
                Logger.WriteWarning(LogMessages.IDX22806);

            if (string.IsNullOrEmpty(roleDescriptor.TokenEndpoint))
                Logger.WriteWarning(LogMessages.IDX22807);

            return roleDescriptor;
        }

        /// <summary>
        /// Read fed:PassiveRequestorEndpoint element in xml.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> used to read PassiveRequestorEndpoint</param>
        /// <returns>token endpoint string</returns>
        /// <exception cref="XmlReadException">if error occurs when reading PassiveRequestorEndpoint</exception>
        protected virtual string ReadPassiveRequestorEndpoint(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Elements.PassiveRequestorEndpoint, Namespaces.FederationNamespace);

            // <PassiveRequestorEndpoint>
            reader.ReadStartElement();
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, Elements.EndpointReference, Namespaces.AddressingNamspace);
            reader.ReadStartElement(Elements.EndpointReference, Namespaces.AddressingNamspace);  // EndpointReference
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, Elements.Address, Namespaces.AddressingNamspace);
            reader.ReadStartElement(Elements.Address, Namespaces.AddressingNamspace);  // Address
            reader.MoveToContent();

            var tokenEndpoint = Trim(reader.ReadContentAsString());

            if (string.IsNullOrEmpty(tokenEndpoint))
                throw XmlUtil.LogReadException(LogMessages.IDX22803);

            // </Address>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </EndpointReference>
            reader.MoveToContent();
            reader.ReadEndElement();

            // </PassiveRequestorEndpoint>
            reader.MoveToContent();
            reader.ReadEndElement();

            return tokenEndpoint;
        }

        private bool IsSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(Elements.RoleDescriptor, Namespaces.MetadataNamespace))
                return false;

            var type = reader.GetAttribute(Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            var typeQualifiedName = new XmlQualifiedName();

            if (!string.IsNullOrEmpty(type))
                typeQualifiedName = XmlUtil.ResolveQName(reader, type);

            if (!XmlUtil.EqualsQName(typeQualifiedName, Types.SecurityTokenServiceType, Namespaces.FederationNamespace))
                return false;

            return true;
        }

        internal static string Trim(string stringToTrim)
        {
            if (string.IsNullOrEmpty(stringToTrim))
                return stringToTrim;

            char[] charsToTrim = { ' ', '\n' };
            return stringToTrim.Trim(charsToTrim);
        }

#endregion

#region Write Metadata

        /// <summary>
        /// Write the content in configuration into writer.
        /// </summary>
        /// <param name="writer">The <see cref="XmlWriter"/> used to write the configuration content.</param>
        /// <param name="configuration">The <see cref="WsFederationConfiguration"/> provided.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> or <paramref name="configuration"/> parameter is missing.</exception>
        /// <exception cref="XmlWriteException">if error occurs when writing metadata.</exception>
        public void WriteMetadata(XmlWriter writer, WsFederationConfiguration configuration)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (configuration == null)
                throw LogArgumentNullException(nameof(configuration));

            if (configuration.SigningCredentials != null)
                writer = new EnvelopedSignatureWriter(writer, configuration.SigningCredentials, "id");

            if (string.IsNullOrEmpty(configuration.Issuer))
                throw XmlUtil.LogWriteException(LogMessages.IDX22810);

            if (string.IsNullOrEmpty(configuration.TokenEndpoint))
                throw XmlUtil.LogWriteException(LogMessages.IDX22811);

            writer.WriteStartDocument();

            // <EntityDescriptor>
            writer.WriteStartElement(Elements.EntityDescriptor, Namespaces.MetadataNamespace);

            // @entityID
            writer.WriteAttributeString(Attributes.EntityId, configuration.Issuer);

            // <RoleDescriptor>
            writer.WriteStartElement(Elements.RoleDescriptor);
            writer.WriteAttributeString(Xmlns, Prefixes.Xsi, null, XmlSignatureConstants.XmlSchemaNamespace);
            writer.WriteAttributeString(Xmlns, Prefixes.Fed, null, Namespaces.FederationNamespace);
            writer.WriteAttributeString(Prefixes.Xsi, Attributes.Type, null, Prefixes.Fed + ":" + Types.SecurityTokenServiceType);

            // write the key infos
            if (configuration.KeyInfos != null)
            {
                foreach (var keyInfo in configuration.KeyInfos)
                {
                    // <KeyDescriptor>
                    writer.WriteStartElement(Elements.KeyDescriptor);
                    writer.WriteAttributeString(Attributes.Use, keyUse.Signing);
                    _dsigSerializer.WriteKeyInfo(writer, keyInfo);
                    // </KeyDescriptor>
                    writer.WriteEndElement();
                }
            }

            // <fed:PassiveRequestorEndpoint>
            writer.WriteStartElement(Elements.PassiveRequestorEndpoint, Namespaces.FederationNamespace);

            // <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
            writer.WriteStartElement(Prefixes.Wsa, Elements.EndpointReference, Namespaces.AddressingNamspace);

            // <wsa:Address>
            writer.WriteStartElement(Elements.Address, Namespaces.AddressingNamspace);

            // write TokenEndpoint
            writer.WriteString(configuration.TokenEndpoint);

            // </wsa:Address>
            writer.WriteEndElement();

            // </wsa:EndpointReference>
            writer.WriteEndElement();

            // </fed:PassiveRequestorEndpoint>
            writer.WriteEndElement();

            // </RoleDescriptor>
            writer.WriteEndElement();

            // </EntityDescriptor>
            writer.WriteEndElement();

            writer.WriteEndDocument();
        }

#endregion
    }
}
