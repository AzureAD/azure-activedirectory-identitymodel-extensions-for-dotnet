//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.Configuration;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IdentityModel.Configuration;
    using System.IdentityModel.Selectors;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel.Security;
    using System.Xml;

    using Attributes = System.IdentityModel.Tokens.JwtConfigurationStrings.Attributes;
    using AttributeValues = System.IdentityModel.Tokens.JwtConfigurationStrings.AttributeValues;
    using Elements = System.IdentityModel.Tokens.JwtConfigurationStrings.Elements;

    /// <summary>
    /// Provides a location for settings that control how the <see cref="JwtSecurityTokenHandler"/> validates or creates a <see cref="JwtSecurityToken"/>. 
    /// </summary>
    /// <remarks>These values have precedence over <see cref="SecurityTokenHandler.Configuration"/>.</remarks>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    public class JwtSecurityTokenRequirement
    {
        /// <summary>
        /// The default clock skew.
        /// </summary>
        public static readonly Int32 DefaultClockSkewInSeconds = 300;

        /// <summary>
        /// The default maximum size of a token that the runtime will process.
        /// </summary>
        public static readonly Int32 DefaultMaximumTokenSizeInBytes = 2 * 1024 * 1024; // 2MB


        // The defaults will only be used if some verification properties are set in config and others are not
        private X509CertificateValidator certificateValidator;
        private X509RevocationMode defaultRevocationMode = X509RevocationMode.Online;
        private StoreLocation defaultStoreLocation = StoreLocation.LocalMachine;
        private int defaultTokenLifetimeInMinutes = 600;
        private X509CertificateValidationMode defaultValidationMode = X509CertificateValidationMode.PeerOrChainTrust;
        private int maxTokenSizeInBytes = 2 * 1024 * 1024;
        private string nameClaimType;
        private string roleClaimType;

        // This indicates that the clockSkew was never set
        //private TimeSpan? maxClockSkew = null;
        private Int32 clockSkewInSeconds = JwtSecurityTokenRequirement.DefaultClockSkewInSeconds;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityTokenRequirement"/> class. 
        /// </summary>
        public JwtSecurityTokenRequirement()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtSecurityTokenRequirement"/> class.
        /// </summary>
        /// <remarks>
        /// <para>A single XML element is expected with up to four optional attributes: {'expected values'} and up to five optional child elements.</para>
        /// <para>&lt;jwtSecurityTokenRequirement</para>
        /// <para>&#160;&#160;&#160;&#160;issuerCertificateRevocationMode: {NoCheck, OnLine, OffLine}</para>
        /// <para>&#160;&#160;&#160;&#160;issuerCertificateTrustedStoreLocation: {CurrentUser, LocalMachine}</para>
        /// <para>&#160;&#160;&#160;&#160;issuerCertificateValidator: type derived from <see cref="X509CertificateValidator"/></para>
        /// <para>&#160;&#160;&#160;&#160;issuerCertificateValidationMode: {ChainTrust, Custom, None, PeerTrust, PeerOrChainTrust}</para>
        /// <para>></para>
        /// <para>&#160;&#160;&#160;&#160;&lt;nameClaimType value = 'user defined type'/></para>
        /// <para>&#160;&#160;&#160;&#160;&lt;roleClaimType value = 'user defined type'/></para>
        /// <para>&#160;&#160;&#160;&#160;&lt;defaultTokenLifetimeInMinutes value = 'uint'/></para>
        /// <para>&#160;&#160;&#160;&#160;&lt;maxTokenSizeInBytes value = 'uint'/></para>
        /// <para>&#160;&#160;&#160;&#160;&lt;maxClockSkewInMinutes value = 'uint'/></para>
        /// <para>&lt;/jwtSecurityTokenRequirement></para>
        /// </remarks>
        /// <param name="element">The <see cref="XmlElement"/> to be parsed.</param>
        /// <exception cref="ArgumentNullException">'element' is null.</exception>
        /// <exception cref="ConfigurationErrorsException"><see cref="XmlElement.LocalName"/> is not 'jwtSecurityTokenRequirement'.</exception>
        /// <exception cref="ConfigurationErrorsException">if a <see cref="XmlAttribute.LocalName"/> is not expected.</exception>
        /// <exception cref="ConfigurationErrorsException">a <see cref="XmlAttribute.Value"/> of &lt;jwtSecurityTokenRequirement> is null or whitespace.</exception>
        /// <exception cref="ConfigurationErrorsException">a <see cref="XmlAttribute.Value"/> is not expected.</exception>
        /// <exception cref="ConfigurationErrorsException">if the <see cref="XmlElement.LocalName"/> of a child element of &lt;jwtSecurityTokenRequirement> is not expected.</exception>
        /// <exception cref="ConfigurationErrorsException">if a child element of &lt;jwtSecurityTokenRequirement> is not well formed.</exception>
        /// <exception cref="ConfigurationErrorsException">if the 'issuerCertificateValidationMode' == 'Custom' and a 'issuerCertificateValidator' attribute was not specified.</exception>
        /// <exception cref="ConfigurationErrorsException">if the runtime was not able to create the type specified by a the 'issuerCertificateValidator' attribute.</exception>
        /// <exception cref="ConfigurationErrorsException">if a child element of &lt;jwtSecurityTokenRequirement> is not well formed.</exception>
        [SuppressMessage("StyleCop.CSharp.ReadabilityRules", "SA1118:ParameterMustNotSpanMultipleLines", Justification = "Reviewed. Suppression is OK here.")]
        public JwtSecurityTokenRequirement(XmlElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException("element");
            }

            if (element.LocalName != Elements.JwtSecurityTokenRequirement)
            {
                throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10601, element.LocalName, element.OuterXml));
            }

            X509RevocationMode revocationMode = this.defaultRevocationMode;
            X509CertificateValidationMode certificateValidationMode = this.defaultValidationMode;
            StoreLocation trustedStoreLocation = this.defaultStoreLocation;
            string customValidator = null;
            bool createCertificateValidator = false;
            HashSet<string> itemsProcessed = new HashSet<string>();

            foreach (XmlAttribute attribute in element.Attributes)
            {
                if (string.IsNullOrWhiteSpace(attribute.Value))
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10600, attribute.LocalName, element.OuterXml));
                }

                if (itemsProcessed.Contains(attribute.Value))
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10617, attribute.LocalName, element.OuterXml));
                }

                if (StringComparer.OrdinalIgnoreCase.Equals(attribute.LocalName, Attributes.Validator))
                {
                    customValidator = attribute.Value;
                }
                else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.LocalName, Attributes.RevocationMode))
                {
                    createCertificateValidator = true;

                    if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509RevocationModeNoCheck))
                    {
                        revocationMode = X509RevocationMode.NoCheck;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509RevocationModeOffline))
                    {
                        revocationMode = X509RevocationMode.Offline;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509RevocationModeOnline))
                    {
                        revocationMode = X509RevocationMode.Online;
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(
                            string.Format(
                                CultureInfo.InvariantCulture,
                                JwtErrors.Jwt10606,
                                Attributes.RevocationMode,
                                attribute.Value,
                                string.Format(
                                    CultureInfo.InvariantCulture,
                                    "'{0}', '{1}', '{2}'",
                                    AttributeValues.X509RevocationModeNoCheck,
                                    AttributeValues.X509RevocationModeOffline,
                                    AttributeValues.X509RevocationModeOnline),
                                element.OuterXml));
                    }
                }
                else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.LocalName, Attributes.ValidationMode))
                {
                    createCertificateValidator = true;

                    if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509CertificateValidationModeChainTrust))
                    {
                        certificateValidationMode = X509CertificateValidationMode.ChainTrust;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509CertificateValidationModePeerOrChainTrust))
                    {
                        certificateValidationMode = X509CertificateValidationMode.PeerOrChainTrust;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509CertificateValidationModePeerTrust))
                    {
                        certificateValidationMode = X509CertificateValidationMode.PeerTrust;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509CertificateValidationModeNone))
                    {
                        certificateValidationMode = X509CertificateValidationMode.None;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509CertificateValidationModeCustom))
                    {
                        certificateValidationMode = X509CertificateValidationMode.Custom;
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(
                            string.Format(
                                CultureInfo.InvariantCulture,
                                JwtErrors.Jwt10606,
                                Attributes.ValidationMode,
                                attribute.Value,
                                string.Format(
                                    CultureInfo.InvariantCulture,
                                    "'{0}', '{1}', '{2}', '{3}', '{4}'",
                                    AttributeValues.X509CertificateValidationModeChainTrust,
                                    AttributeValues.X509CertificateValidationModePeerOrChainTrust,
                                    AttributeValues.X509CertificateValidationModePeerTrust,
                                    AttributeValues.X509CertificateValidationModeNone,
                                    AttributeValues.X509CertificateValidationModeCustom),
                                element.OuterXml));
                    }
                }
                else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.LocalName, Attributes.TrustedStoreLocation))
                {
                    createCertificateValidator = true;

                    if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509TrustedStoreLocationCurrentUser))
                    {
                        trustedStoreLocation = StoreLocation.CurrentUser;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(attribute.Value, AttributeValues.X509TrustedStoreLocationLocalMachine))
                    {
                        trustedStoreLocation = StoreLocation.LocalMachine;
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(
                            string.Format(
                                CultureInfo.InvariantCulture,
                                JwtErrors.Jwt10606,
                                Attributes.TrustedStoreLocation,
                                attribute.Value,
                                "'" + AttributeValues.X509TrustedStoreLocationCurrentUser + "', '" + AttributeValues.X509TrustedStoreLocationLocalMachine + "'",
                                element.OuterXml));
                    }
                }
                else
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10608, Elements.JwtSecurityTokenRequirement, attribute.LocalName, element.OuterXml));
                }
            }

            List<XmlElement> configElements = XmlUtil.GetXmlElements(element.ChildNodes);
            HashSet<string> elementsProcessed = new HashSet<string>();

            foreach (XmlElement childElement in configElements)
            {
                if (childElement.Attributes.Count > 1)
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10609, childElement.LocalName, Attributes.Value, element.OuterXml));
                }

                if (childElement.Attributes.Count == 0)
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10607, childElement.LocalName, Attributes.Value, element.OuterXml));
                }

                if (string.IsNullOrWhiteSpace(childElement.Attributes[0].LocalName))
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10600, Attributes.Value, element.OuterXml));
                }

                if (!StringComparer.Ordinal.Equals(childElement.Attributes[0].LocalName, Attributes.Value))
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10610, childElement.LocalName, Attributes.Value, childElement.Attributes[0].LocalName, element.OuterXml));
                }

                if (elementsProcessed.Contains(childElement.LocalName))
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10616, childElement.LocalName, element.OuterXml));
                }

                elementsProcessed.Add(childElement.LocalName);

                if (StringComparer.Ordinal.Equals(childElement.LocalName, Elements.NameClaimType))
                {
                    this.NameClaimType = childElement.Attributes[0].Value;
                }
                else if (StringComparer.Ordinal.Equals(childElement.LocalName, Elements.RoleClaimType))
                {
                    this.RoleClaimType = childElement.Attributes[0].Value;
                }
                else
                {
                    try
                    {
                        if (StringComparer.Ordinal.Equals(childElement.LocalName, Elements.MaxTokenSizeInBytes))
                        {
                            this.MaximumTokenSizeInBytes = Convert.ToInt32(childElement.Attributes[0].Value, CultureInfo.InvariantCulture);
                        }
                        else if (StringComparer.Ordinal.Equals(childElement.LocalName, Elements.DefaultTokenLifetimeInMinutes))
                        {
                            this.DefaultTokenLifetimeInMinutes = Convert.ToInt32(childElement.Attributes[0].Value, CultureInfo.InvariantCulture);
                        }
                        else if (StringComparer.Ordinal.Equals(childElement.LocalName, Elements.MaxClockSkewInMinutes))
                        {
                            this.ClockSkewInSeconds = Convert.ToInt32(childElement.Attributes[0].Value, CultureInfo.InvariantCulture);
                        }
                        else
                        {
                            throw new ConfigurationErrorsException(
                                string.Format(
                                    CultureInfo.InvariantCulture,
                                    JwtErrors.Jwt10611,
                                    Elements.JwtSecurityTokenRequirement,
                                    childElement.LocalName,
                                    string.Format(
                                        CultureInfo.InvariantCulture,
                                        "{0}', '{1}', '{2}', '{3}', '{4}",
                                        Elements.NameClaimType,
                                        Elements.RoleClaimType,
                                        Elements.MaxTokenSizeInBytes,
                                        Elements.MaxClockSkewInMinutes,
                                        Elements.DefaultTokenLifetimeInMinutes),
                                    element.OuterXml));
                        }
                    }
                    catch (OverflowException oex)
                    {
                        throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10603, childElement.LocalName, childElement.OuterXml, oex), oex);
                    }
                    catch (FormatException fex)
                    {
                        throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10603, childElement.LocalName, childElement.OuterXml, fex), fex);
                    }
                    catch (ArgumentOutOfRangeException aex)
                    {
                        throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10603, childElement.LocalName, childElement.OuterXml, aex), aex);
                    }
                }
            }

            if (certificateValidationMode == X509CertificateValidationMode.Custom)
            {
                Type customValidatorType = null;

                if (customValidator == null)
                {
                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10612, Attributes.ValidationMode, Attributes.Validator, element.OuterXml));
                }

                try
                {
                    customValidatorType = Type.GetType(customValidator, true);
                    CustomTypeElement typeElement = new CustomTypeElement();
                    typeElement.Type = customValidatorType;

                    this.certificateValidator = CustomTypeElement.Resolve<X509CertificateValidator>(typeElement);
                }
                catch (Exception ex)
                {
                    if (DiagnosticUtility.IsFatal(ex))
                    {
                        throw;
                    }

                    throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10613, customValidator, Attributes.Validator, ex, element.OuterXml), ex);
                }
            }
            else if (customValidator != null)
            {
                throw new ConfigurationErrorsException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10619, Attributes.Validator, Attributes.ValidationMode, AttributeValues.X509CertificateValidationModeCustom, certificateValidationMode, typeof(X509CertificateValidator).ToString(), customValidator, element.OuterXml));
            }
            else if (createCertificateValidator)
            {
                this.certificateValidator = new X509CertificateValidatorEx(certificateValidationMode, revocationMode, trustedStoreLocation);
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="X509CertificateValidator"/> for validating <see cref="X509Certificate2"/>(s).
        /// </summary>
        public X509CertificateValidator CertificateValidator
        {
            get
            {
                return this.certificateValidator;
            }

            set
            {
                this.certificateValidator = value;
            }
        }

        /// <summary>
        /// Gets or sets the clock skew to use when validating times.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"> if 'value' is less than 0.</exception>
        public Int32 ClockSkewInSeconds
        {
            get
            {
                return this.clockSkewInSeconds;
            }

            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(JwtErrors.Jwt10120);
                }

                this.clockSkewInSeconds = value;
            }
        }

        /// <summary>
        /// Gets or sets the default for token lifetime.
        /// <see cref="JwtSecurityTokenHandler"/> uses this value when creating a <see cref="JwtSecurityToken"/> if the expiration time is not specified.  The expiration time will be set to <see cref="DateTime.UtcNow"/> + <see cref="TimeSpan.FromMinutes"/> with <see cref="JwtSecurityTokenRequirement.DefaultTokenLifetimeInMinutes"/> as the parameter.
        /// </summary>
        /// <remarks>Default: 600 (10 hours).</remarks>
        /// <exception cref="ArgumentOutOfRangeException">value == 0.</exception>
        public Int32 DefaultTokenLifetimeInMinutes
        {
            get
            {
                return this.defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException("value", JwtErrors.Jwt10115);
                }

                this.defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets the maximum size of a <see cref="JwtSecurityToken"/> the <see cref="JwtSecurityTokenHandler"/> will read and validate.
        /// </summary>
        /// <remarks>Default: 2 megabytes.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">if value is 0.</exception>
        public Int32 MaximumTokenSizeInBytes
        {
            get
            {
                return this.maxTokenSizeInBytes;
            }

            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException("value", JwtErrors.Jwt10116);
                }

                this.maxTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="string"/> the <see cref="JwtSecurityTokenHandler"/> passes as a parameter to <see cref="ClaimsIdentity(string, string, string)"/>. 
        /// <para>This defines the <see cref="Claim.Type"/> to match when finding the <see cref="Claim.Value"/> that is used for the <see cref="ClaimsIdentity.Name"/> property.</para>
        /// </summary>
        public string NameClaimType
        {
            get
            {
                return this.nameClaimType;
            }

            set
            {
                this.nameClaimType = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="string"/> the <see cref="JwtSecurityTokenHandler"/> passes as a parameter to <see cref="ClaimsIdentity(string, string, string)"/>.
        /// <para>This defines the <see cref="Claim"/>(s) that will be considered when answering <see cref="ClaimsPrincipal.IsInRole( string )"/></para>
        /// </summary>
        public string RoleClaimType
        {
            get
            {
                return this.roleClaimType;
            }

            set
            {
                this.roleClaimType = value;
            }
        }
    }
}
