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
using System.Xml.Schema;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Metadata serializer class for WsFed. 
    /// </summary>
    public class WsFederationMetadataSerializer
    {
        /// <summary>
        /// Metadata serializer for WsFed.
        /// </summary>
        public WsFederationMetadataSerializer() { }

        /// <summary>
        /// Read metadata and create the corresponding WsFed configuration.
        /// </summary>
        /// <param name="reader">xml reader</param>
        /// <returns>WsFed configuration</returns>
        public WsFederationConfiguration ReadMetadata(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.EntityDescriptor, WsFederationConstants.Namespaces.MetadataNamespace);

            var configuration = new WsFederationConfiguration();
            var envelopeReader = new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(reader));

            try
            {
                ReadEntityDescriptor(configuration, envelopeReader);
            }
            catch (Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX13000, ex, WsFederationConstants.Elements.EntityDescriptor, ex);
            }

            configuration.Signature = envelopeReader.Signature;

            return configuration;
        }

        /// <summary>
        /// Read EntityDescriptor element in xml.
        /// </summary>
        /// <param name="configuration">WsFed configuration</param>
        /// <param name="reader">xmlreader</param>
        protected virtual void ReadEntityDescriptor(WsFederationConfiguration configuration, XmlReader reader)
        {
            if (configuration == null)
                throw LogHelper.LogArgumentNullException(nameof(configuration));

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.EntityDescriptor, WsFederationConstants.Namespaces.MetadataNamespace);

            // get entityID for issuer
            configuration.Issuer = reader.GetAttribute(WsFederationConstants.Attributes.EntityId);

            if (string.IsNullOrEmpty(configuration.Issuer))
                throw XmlUtil.LogReadException(LogMessages.IDX13001);

            // Process <EntityDescriptor>            
            reader.ReadStartElement();

            // flag for the existence of SecurityTokenSeviceType RoleDescriptor
            var hasSecurityTokenServiceTypeRoleDescriptor = false;

            while (reader.IsStartElement())
            {
                if (IsSecurityTokenServiceTypeRoleDescriptor(reader))
                {
                    hasSecurityTokenServiceTypeRoleDescriptor = true;
                    ReadSecurityTokenServiceTypeRoleDescriptor(configuration, reader);
                }
                else
                {
                    reader.ReadOuterXml();
                }
            }

            // Process </EntityDescriptor>
            reader.ReadEndElement();

            // The metadata xml should contain a SecurityTokenServiceType RoleDescriptor
            if (!hasSecurityTokenServiceTypeRoleDescriptor)
                throw XmlUtil.LogReadException(LogMessages.IDX13004);
        }

        /// <summary>
        /// Read KeyDescriptor element in xml.
        /// </summary>
        /// <param name="configuration">WsFed configuration</param>
        /// <param name="reader">xmlreader</param>
        protected virtual void ReadKeyDescriptorForSigning(WsFederationConfiguration configuration, XmlReader reader)
        {
            if (configuration == null)
                throw LogHelper.LogArgumentNullException(nameof(configuration));

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.KeyDescriptor, WsFederationConstants.Namespaces.MetadataNamespace);

            if (!IsKeyDescriptorForSigning(reader))
                throw XmlUtil.LogReadException(LogMessages.IDX13005);

            // Process <KeyDescriptor>
            reader.ReadStartElement();  

            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
            {
                KeyInfo keyInfo = new KeyInfo();
                keyInfo.ReadFrom(reader);
                configuration.KeyInfos.Add(keyInfo);

                if (!string.IsNullOrEmpty(keyInfo.CertificateData))
                {
                    var cert = new X509Certificate2(Convert.FromBase64String(keyInfo.CertificateData));
                    configuration.SigningKeys.Add(new X509SecurityKey(cert));
                }
            }
            else
            {
                throw XmlUtil.LogReadException(LogMessages.IDX13002, reader.LocalName, reader.NamespaceURI, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);
            }

            // Process </KeyDescriptor>
            reader.ReadEndElement();
        }

        /// <summary>
        /// Read RoleDescriptor element in xml.
        /// </summary>
        /// <param name="configuration">WsFed configuration</param>
        /// <param name="reader">xmlreader</param>
        protected virtual void ReadSecurityTokenServiceTypeRoleDescriptor(WsFederationConfiguration configuration, XmlReader reader)
        {
            if (configuration == null)
                throw LogHelper.LogArgumentNullException(nameof(configuration));

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.RoleDescriptor, WsFederationConstants.Namespaces.MetadataNamespace);

            if (!IsSecurityTokenServiceTypeRoleDescriptor(reader))
                throw XmlUtil.LogReadException(LogMessages.IDX13004);

            // Process <RoleDescriptorr>
            reader.ReadStartElement();

            // Warn if there is no KeyDescriptor element for Signing
            // Throw if there is no SecurityTokenEndpoint element
            var hasKeyDescriptorForSigning = false;
            var hasSecurityTokenEndpoint = false;

            while (reader.IsStartElement())
            {
                if (IsKeyDescriptorForSigning(reader))
                {
                    hasKeyDescriptorForSigning = true;
                    ReadKeyDescriptorForSigning(configuration, reader);
                }
                else if (reader.IsStartElement(WsFederationConstants.Elements.SecurityTokenEndpoint, WsFederationConstants.Namespaces.FederationNamespace))
                {
                    hasSecurityTokenEndpoint = true;
                    ReadSecurityTokenEndpoint(configuration, reader);
                }
                else if (reader.IsStartElement())
                {
                    reader.ReadOuterXml();
                }
                else
                {
                    throw XmlUtil.LogReadException(LogMessages.IDX13003, reader.Name);
                }
            }

            // Process </RoleDescriptorr>
            reader.ReadEndElement();

            if (!hasKeyDescriptorForSigning)
                IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX13006);
            if (!hasSecurityTokenEndpoint)
                throw XmlUtil.LogReadException(LogMessages.IDX13007);
        }

        /// <summary>
        /// Read fed:SecurityTokenServiceEndpoint element in xml.
        /// </summary>
        /// <param name="configuration">WsFed configuration</param>
        /// <param name="reader">xmlreader</param>
        protected virtual void ReadSecurityTokenEndpoint(WsFederationConfiguration configuration, XmlReader reader)
        {
            if (configuration == null)
                throw LogHelper.LogArgumentNullException(nameof(configuration));

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.SecurityTokenEndpoint, WsFederationConstants.Namespaces.FederationNamespace);

            reader.ReadStartElement();  // SecurityTokenServiceEndpoint
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.EndpointReference, WsFederationConstants.Namespaces.AddressingNamspace);
            reader.ReadStartElement(WsFederationConstants.Elements.EndpointReference, WsFederationConstants.Namespaces.AddressingNamspace);  // EndpointReference
            reader.MoveToContent();

            XmlUtil.CheckReaderOnEntry(reader, WsFederationConstants.Elements.Address, WsFederationConstants.Namespaces.AddressingNamspace);
            reader.ReadStartElement(WsFederationConstants.Elements.Address, WsFederationConstants.Namespaces.AddressingNamspace);  // Address
            reader.MoveToContent();

            configuration.TokenEndpoint = Trim(reader.ReadContentAsString());

            if (string.IsNullOrEmpty(configuration.TokenEndpoint))
                throw XmlUtil.LogReadException(LogMessages.IDX13003);

            reader.MoveToContent();
            reader.ReadEndElement();  // Address

            reader.MoveToContent();
            reader.ReadEndElement();  // EndpointReference

            reader.MoveToContent();
            reader.ReadEndElement();  // SecurityTokenServiceEndpoint
        }

        private bool IsKeyDescriptorForSigning(XmlReader reader)
        {
            return null != reader &&
                reader.IsStartElement(WsFederationConstants.Elements.KeyDescriptor, WsFederationConstants.Namespaces.MetadataNamespace) &&
                reader.GetAttribute(WsFederationConstants.Attributes.Use).Equals(WsFederationConstants.keyUse.Signing);
        }

        private bool IsSecurityTokenServiceTypeRoleDescriptor(XmlReader reader)
        {
            if (reader == null || !reader.IsStartElement(WsFederationConstants.Elements.RoleDescriptor, WsFederationConstants.Namespaces.MetadataNamespace))
                return false;

            var type = reader.GetAttribute(WsFederationConstants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
            var typeQualifiedName = new XmlQualifiedName();

            if (!string.IsNullOrEmpty(type))
                typeQualifiedName = XmlUtil.ResolveQName(reader, type);

            if (!XmlUtil.EqualsQName(typeQualifiedName, WsFederationConstants.Types.SecurityTokenServiceType, WsFederationConstants.Namespaces.FederationNamespace))
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
    }
}
