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

using Microsoft.IdentityModel.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using Attributes = System.IdentityModel.Tokens.JwtConfigurationStrings.Attributes;
using AttributeValues = System.IdentityModel.Tokens.JwtConfigurationStrings.AttributeValues;
using CertMode = System.ServiceModel.Security.X509CertificateValidationMode;
using Elements = System.IdentityModel.Tokens.JwtConfigurationStrings.Elements;

namespace System.IdentityModel.Test
{
    public class ExpectedJwtSecurityTokenRequirement
    {
        public ExpectedJwtSecurityTokenRequirement
        (
            uint? tokenSize = null, Int32? clock = null, uint? life = null, X509CertificateValidator cert = null, string name = JwtConstants.ReservedClaims.Subject, string role = null, X509RevocationMode? revMode = null, X509CertificateValidationMode? certMode = null, StoreLocation? storeLoc = null, ExpectedException expectedException = null,
            string handler = JwtSecurityTokenHandlerType, string requirement = Elements.JwtSecurityTokenRequirement,
            string attributeEx1 = "", string attributeEx2 = "", string attributeEx3 = "", string attributeEx4 = "",
            string elementEx1 = comment, string elementEx2 = comment, string elementEx3 = comment, string elementEx4 = comment, string elementEx5 = comment, string elementEx6 = comment,
            string elementClose = closeRequirement

        )
        {
            MaxTokenSizeInBytes = tokenSize;
            NameClaimType = name;
            RoleClaimType = role;
            CertValidator = cert;
            ClockSkewInSeconds = clock;
            DefaultTokenLifetimeInMinutes = life;
            CertRevocationMode = revMode;
            CertValidationMode = certMode;
            CertStoreLocation = storeLoc;
            ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected;
            string[] sParams = 
            {
                handler,
                requirement,
                CertRevocationMode == null ? string.Empty : Attribute( Attributes.RevocationMode, CertRevocationMode.Value.ToString() ),
                attributeEx1,
                CertValidationMode == null ? string.Empty : Attribute( Attributes.ValidationMode, CertValidationMode.Value.ToString() ),
                attributeEx2,
                CertValidator == null ? string.Empty : Attribute( Attributes.Validator, CertValidator.GetType().ToString() +", System.IdentityModel.Tokens.Jwt.Tests" ),
                attributeEx3,
                CertStoreLocation == null ? string.Empty : Attribute( Attributes.TrustedStoreLocation, CertStoreLocation.ToString() ),
                attributeEx4,
                elementEx1,
                ClockSkewInSeconds == null ? string.Empty : ElementValue( Elements.MaxClockSkewInMinutes, ClockSkewInSeconds.Value.ToString() ),
                elementEx2,
                MaxTokenSizeInBytes == null ? string.Empty : ElementValue( Elements.MaxTokenSizeInBytes, MaxTokenSizeInBytes.Value.ToString() ),
                elementEx3,
                DefaultTokenLifetimeInMinutes == null ? string.Empty : ElementValue( Elements.DefaultTokenLifetimeInMinutes, DefaultTokenLifetimeInMinutes.Value.ToString() ),
                elementEx4,
                NameClaimType == null ? string.Empty : ElementValue( Elements.NameClaimType, NameClaimType ),
                elementEx5,
                RoleClaimType == null ? string.Empty : ElementValue( Elements.RoleClaimType, RoleClaimType ),
                elementEx6,
                elementClose,
            };
            Config = string.Format(ElementTemplate, sParams);
        }

        public bool AsExpected(JwtSecurityTokenRequirement requirement)
        {
            bool asExpected = true;

            JwtSecurityTokenRequirement controlRequirement = new JwtSecurityTokenRequirement();
            if (requirement == null)
            {
                return false;
            }

            Assert.IsFalse(
                MaxTokenSizeInBytes != null && MaxTokenSizeInBytes.Value != requirement.MaximumTokenSizeInBytes,
                string.Format(CultureInfo.InvariantCulture,
                    "MaximumTokenSizeInBytes (expected, config): '{0}'. '{1}'.",
                    MaxTokenSizeInBytes.ToString(),
                    requirement.MaximumTokenSizeInBytes.ToString()));
            Assert.IsFalse(
                MaxTokenSizeInBytes == null
                && requirement.MaximumTokenSizeInBytes != controlRequirement.MaximumTokenSizeInBytes,
                string.Format(CultureInfo.InvariantCulture,
                    "MaximumTokenSizeInBytes should be default (default, config): '{0}'. '{1}'.",
                    controlRequirement.MaximumTokenSizeInBytes.ToString(),
                    requirement.MaximumTokenSizeInBytes.ToString()));

            Assert.IsFalse(
                ClockSkewInSeconds != null && ClockSkewInSeconds.Value != requirement.ClockSkewInSeconds,
                string.Format(CultureInfo.InvariantCulture,
                    "ClockSkew (expected, config): '{0}'. '{1}'.",
                    ClockSkewInSeconds.ToString(),
                    requirement.ClockSkewInSeconds.ToString()));
            Assert.IsFalse(
                ClockSkewInSeconds == null && requirement.ClockSkewInSeconds != controlRequirement.ClockSkewInSeconds,
                string.Format(CultureInfo.InvariantCulture,
                    "ClockSkew should be default (default, config): '{0}'. '{1}'.",
                    controlRequirement.ClockSkewInSeconds.ToString(),
                    requirement.ClockSkewInSeconds.ToString()));

            Assert.IsFalse(
                DefaultTokenLifetimeInMinutes != null
                && DefaultTokenLifetimeInMinutes.Value != requirement.DefaultTokenLifetimeInMinutes,
                string.Format(CultureInfo.InvariantCulture,
                    "DefaultTokenLifetimeInMinutes (expected, config): '{0}'. '{1}'.",
                    DefaultTokenLifetimeInMinutes.ToString(),
                    requirement.DefaultTokenLifetimeInMinutes.ToString()));
            Assert.IsFalse(
                DefaultTokenLifetimeInMinutes == null
                && requirement.DefaultTokenLifetimeInMinutes != controlRequirement.DefaultTokenLifetimeInMinutes,
                string.Format(CultureInfo.InvariantCulture,
                    "DefaultTokenLifetimeInMinutes should be default (default, config): '{0}'. '{1}'.",
                    controlRequirement.DefaultTokenLifetimeInMinutes.ToString(),
                    requirement.DefaultTokenLifetimeInMinutes.ToString()));

            // make sure nameclaim and roleclaim are same, or null together.
            Assert.IsFalse(NameClaimType == null && requirement.NameClaimType != null, "NameClaimType == null && requirement.NameClaimType != null");

            Assert.IsFalse(NameClaimType != null && requirement.NameClaimType == null, "NameClaimType != null && requirement.NameClaimType == null");

            if ((NameClaimType != null && requirement.NameClaimType != null)
            && (NameClaimType != requirement.NameClaimType))
            {
                Assert.Fail(string.Format(CultureInfo.InvariantCulture, "NameClaimType (expected, config): '{0}'. '{1}'.", NameClaimType, requirement.NameClaimType));
                asExpected = false;
            }

            Assert.IsFalse(RoleClaimType == null && requirement.RoleClaimType != null, "RoleClaimType == null && requirement.RoleClaimType != null");

            Assert.IsFalse(RoleClaimType != null && requirement.RoleClaimType == null, "RoleClaimType != null && requirement.RoleClaimType == null");

            if ((RoleClaimType != null && requirement.RoleClaimType != null)
            && (RoleClaimType != requirement.RoleClaimType))
            {
                Assert.Fail(string.Format(CultureInfo.InvariantCulture, "RoleClaimType (expected, config): '{0}'. '{1}'.", RoleClaimType, requirement.RoleClaimType));
                asExpected = false;
            }

            // != null => this variation sets a custom validator.
            if (CertValidator != null)
            {
                if (requirement.CertificateValidator == null)
                {
                    return false;
                }

                Assert.IsFalse(CertValidator.GetType() != requirement.CertificateValidator.GetType(), string.Format("CertificateValidator.GetType() != requirement.CertificateValidator.GetType(). (expected, config): '{0}'. '{1}'.", CertValidator.GetType(), requirement.CertificateValidator.GetType()));
            }
            else
            {
                if (CertValidationMode.HasValue || CertRevocationMode.HasValue || CertStoreLocation.HasValue)
                {
                    Assert.IsFalse(requirement.CertificateValidator == null, string.Format("X509CertificateValidationMode.HasValue || X09RevocationMode.HasValue || StoreLocation.HasValue is true, there should be a validator"));

                    // get and check _certificateValidationMode
                    Type type = requirement.CertificateValidator.GetType();

                    FieldInfo fi = type.GetField("validator", BindingFlags.NonPublic | BindingFlags.Instance);
                    X509CertificateValidator validator = (X509CertificateValidator)fi.GetValue(requirement.CertificateValidator);

                    // make sure we created the right validator
                    if (CertValidationMode == CertMode.ChainTrust && (validator.GetType() != X509CertificateValidator.ChainTrust.GetType())
                    || CertValidationMode == CertMode.PeerTrust && (validator.GetType() != X509CertificateValidator.PeerTrust.GetType())
                    || CertValidationMode == CertMode.PeerOrChainTrust && (validator.GetType() != X509CertificateValidator.PeerOrChainTrust.GetType())
                    || CertValidationMode == CertMode.None && (validator.GetType() != X509CertificateValidator.None.GetType()))
                    {
                        Assert.Fail(string.Format(CultureInfo.InvariantCulture, "X509CertificateValidator type. expected: '{0}', actual: '{1}'", CertValidationMode.HasValue ? CertValidationMode.Value.ToString() : "null", validator.GetType().ToString()));
                        asExpected = false;
                    }

                    // if  these 'Modes' HasValue, then it should be matched, otherwise expect default.
                    fi = type.GetField("certificateValidationMode", BindingFlags.NonPublic | BindingFlags.Instance);
                    CertMode certMode = (CertMode)fi.GetValue(requirement.CertificateValidator);
                    if (CertValidationMode.HasValue)
                    {
                        Assert.IsFalse(CertValidationMode.Value != certMode, string.Format(CultureInfo.InvariantCulture, "X509CertificateValidationMode. expected: '{0}', actual: '{1}'", CertValidationMode.Value.ToString(), certMode.ToString()));
                        // if mode includes chain  building, revocation mode Policy s/b null.

                        if (CertValidationMode.Value == X509CertificateValidationMode.ChainTrust
                            || CertValidationMode.Value == X509CertificateValidationMode.PeerOrChainTrust)
                        {
                            // check inner policy
                            if (CertRevocationMode.HasValue)
                            {
                                fi = type.GetField("chainPolicy", BindingFlags.NonPublic | BindingFlags.Instance);
                                X509ChainPolicy chainPolicy =
                                    (X509ChainPolicy)fi.GetValue(requirement.CertificateValidator);

                                Assert.IsFalse(
                                    chainPolicy.RevocationMode != CertRevocationMode.Value,
                                    string.Format(
                                        CultureInfo.InvariantCulture,
                                        "chainPolicy.RevocationMode.  . expected: '{0}', actual: '{1}'",
                                        CertRevocationMode.Value.ToString(),
                                        chainPolicy.RevocationMode.ToString()));
                            }
                        }
                    }
                }
            }
            return asExpected;
        }

        public uint? MaxTokenSizeInBytes { get; set; }
        public Int32? ClockSkewInSeconds { get; set; }
        public string NameClaimType { get; set; }
        public string RoleClaimType { get; set; }
        public X509CertificateValidator CertValidator { get; set; }
        public uint? DefaultTokenLifetimeInMinutes { get; set; }
        public X509RevocationMode? CertRevocationMode { get; set; }
        public X509CertificateValidationMode? CertValidationMode { get; set; }
        public StoreLocation? CertStoreLocation { get; set; }
        public ExpectedException ExpectedException { get; set; }
        public string Config { get; set; }

        public const string ElementTemplate = @"<add type='{0}'><{1} {2} {3} {4} {5} {6} {7} {8} {9} >{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}</add>";
        public const string JwtSecurityTokenHandlerType = "System.IdentityModel.Tokens.JwtSecurityTokenHandler, System.IdentityModel.Tokens.Jwt";
        public const string AlwaysSucceedCertificateValidator = "System.IdentityModel.Test.AlwaysSucceedCertificateValidator, System.IdentityModel.Tokens.Jwt.Test";
        public const string comment = @"<!-- Comment -->";
        public const string closeRequirement = "</" + Elements.JwtSecurityTokenRequirement + ">";

        public static string CloseElement(string element) { return "</" + element + ">"; }
        public static string ElementValue(string element, string value) { return "<" + element + " " + Attributes.Value + "='" + value + "' />"; }
        public static string Attribute(string attribute, string value) { return attribute + "='" + value + "'"; }


        public string[] StringParams(string handler = JwtSecurityTokenHandlerType, string requirement = Elements.JwtSecurityTokenRequirement,
                                      string attributeEx1 = "", string attributeEx2 = "", string attributeEx3 = "", string attributeEx4 = "",
                                      string elementEx1 = comment, string elementEx2 = comment, string elementEx3 = comment, string elementEx4 = comment, string elementEx5 = comment, string elementEx6 = comment,
                                      string elementClose = closeRequirement)
        {
            return new string[]
            {
                handler,
                requirement,
                CertRevocationMode == null ? string.Empty : Attribute( Attributes.RevocationMode, CertRevocationMode.Value.ToString() ),
                attributeEx1,
                CertValidationMode == null ? string.Empty : Attribute( Attributes.ValidationMode, CertValidationMode.Value.ToString() ),
                attributeEx2,
                CertValidator == null ? string.Empty : Attribute( Attributes.Validator, CertValidator.GetType().ToString() +", System.IdentityModel.Tokens.JWT.Test" ),
                attributeEx3,
                CertStoreLocation == null ? string.Empty : Attribute( Attributes.TrustedStoreLocation, CertStoreLocation.ToString() ),
                attributeEx4,
                elementEx1,
                ClockSkewInSeconds == null ? string.Empty : ElementValue( Elements.MaxClockSkewInMinutes, ClockSkewInSeconds.Value.ToString() ),
                elementEx2,
                MaxTokenSizeInBytes == null ? string.Empty : ElementValue( Elements.MaxTokenSizeInBytes, MaxTokenSizeInBytes.Value.ToString() ),
                elementEx3,
                DefaultTokenLifetimeInMinutes == null ? string.Empty : ElementValue( Elements.DefaultTokenLifetimeInMinutes, DefaultTokenLifetimeInMinutes.Value.ToString() ),
                elementEx4,
                NameClaimType == null ? string.Empty : ElementValue( Elements.NameClaimType, NameClaimType ),
                elementEx5,
                RoleClaimType == null ? string.Empty : ElementValue( Elements.RoleClaimType, RoleClaimType ),
                elementEx6,
                elementClose,
            };
        }

    };

    public class JwtHandlerConfigVariation
    {
        public ExpectedJwtSecurityTokenRequirement ExpectedJwtSecurityTokenRequirement { get; set; }
        public JwtSecurityTokenHandler ExpectedSecurityTokenHandler { get; set; }
        public static List<ExpectedJwtSecurityTokenRequirement> RequirementVariations;
        public static string ElementValue(string element, string value, string attributeValue = Attributes.Value, int count = 1)
        {
            string attributePart = string.Empty;
            string postfix = string.Empty;
            for (int i = 0; i < count; i++)
            {
                attributePart += attributeValue + (i == 0 ? string.Empty : i.ToString()) + "='" + value + "' ";
            }

            return "<" + element + " " + attributePart + " />";
        }

        //public static string ElementValue( string element, string value, string attributeValue = Attributes.Value ) { return "<" + element + " " + attributeValue + "='" + value + "' />"; }
        public static string ElementValueMultipleAttributes(string element, string value, string value2) { return "<" + element + " " + Attributes.Value + "='" + value + " " + Attributes.Value + "='" + value2 + "' />"; }
        public static string Attribute(string attribute, string value) { return attribute + "='" + value + "'"; }

        public static void BuildExpectedRequirements()
        {
            RequirementVariations = new List<ExpectedJwtSecurityTokenRequirement>();

            // Empty Element
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: "<>", expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));

            // unknown element
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue("UnknownElement", "@http://AllItemsSet/nameClaim"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10611")));

            // element.Localname empty
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue("", "@http://AllItemsSet/nameClaim"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));

            // Element attribute name is not 'value'
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "6000", attributeValue: "NOTvalue"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10610:")));

            // Attribute name empty
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(attributeEx1: Attribute("", AttributeValues.X509CertificateValidationModeChainTrust), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));

            // Attribute value empty
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(attributeEx1: Attribute(Attributes.ValidationMode, ""), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10600", inner: typeof(InvalidOperationException))));

            // Multiple Attributes
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.NameClaimType, "Bob", count: 2), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10609")));

            // No Attributes
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.NameClaimType, "Bob", count: 0), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10607")));

            // for each variation, make sure a validator is created.
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(revMode: X509RevocationMode.NoCheck, storeLoc: StoreLocation.CurrentUser, certMode: X509CertificateValidationMode.ChainTrust, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(revMode: X509RevocationMode.Offline, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(revMode: X509RevocationMode.Online, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.ChainTrust, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.Custom, expectedException: ExpectedException.ConfigurationErrorsException("Jwt10612")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.None, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.PeerOrChainTrust, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.PeerTrust, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(storeLoc: StoreLocation.CurrentUser, expectedException: ExpectedException.NoExceptionExpected));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(storeLoc: StoreLocation.LocalMachine, expectedException: ExpectedException.NoExceptionExpected));

            // Error Conditions - lifetime
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(life: 0, expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(ArgumentOutOfRangeException), substringExpected: "Jwt10603")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "-1"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(ArgumentOutOfRangeException), substringExpected: "Jwt10603")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "abc"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(FormatException))));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "15372286729"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(OverflowException))));

            // Error Conditions - tokensSize
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 0, expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(ArgumentOutOfRangeException), substringExpected: "Jwt10603")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.MaxTokenSizeInBytes, "-1"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(ArgumentOutOfRangeException), substringExpected: "Jwt10603")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.MaxTokenSizeInBytes, "abc"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(FormatException))));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(elementEx1: ElementValue(Elements.MaxTokenSizeInBytes, "4294967296"), expectedException: ExpectedException.ConfigurationErrorsException(inner: typeof(OverflowException))));

            // Duplicate Elements, we have to catch them.
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000, revMode: X509RevocationMode.NoCheck, elementEx1: ElementValue(Elements.MaxTokenSizeInBytes, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000, revMode: X509RevocationMode.NoCheck, elementEx3: ElementValue(Elements.MaxTokenSizeInBytes, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(name: @"http://AllItemsSet/nameClaim", revMode: X509RevocationMode.NoCheck, elementEx3: ElementValue(Elements.NameClaimType, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(name: @"http://AllItemsSet/nameClaim", revMode: X509RevocationMode.NoCheck, elementEx5: ElementValue(Elements.NameClaimType, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(role: @"http://AllItemsSet/roleClaim", revMode: X509RevocationMode.NoCheck, elementEx3: ElementValue(Elements.RoleClaimType, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(role: @"http://AllItemsSet/roleClaim", revMode: X509RevocationMode.NoCheck, elementEx6: ElementValue(Elements.RoleClaimType, "1024"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(clock: 15, certMode: X509CertificateValidationMode.PeerTrust, elementEx1: ElementValue(Elements.MaxClockSkewInMinutes, "5"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(clock: 15, revMode: X509RevocationMode.NoCheck, elementEx2: ElementValue(Elements.MaxClockSkewInMinutes, "5"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(life: 1000, revMode: X509RevocationMode.NoCheck, elementEx1: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "60"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(life: 1000, revMode: X509RevocationMode.NoCheck, elementEx4: ElementValue(Elements.DefaultTokenLifetimeInMinutes, "60"), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "Jwt10616")));

            // Duplicate Attributes, System.Configuration will catch them.
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(revMode: X509RevocationMode.NoCheck, attributeEx1: Attribute(Attributes.RevocationMode, AttributeValues.X509RevocationModeNoCheck.ToString()), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.PeerTrust, attributeEx2: Attribute(Attributes.ValidationMode, AttributeValues.X509CertificateValidationModeNone.ToString()), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(storeLoc: StoreLocation.LocalMachine, attributeEx4: Attribute(Attributes.TrustedStoreLocation, StoreLocation.LocalMachine.ToString()), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(cert: new AlwaysSucceedCertificateValidator(), attributeEx1: Attribute(Attributes.Validator, typeof(AlwaysSucceedCertificateValidator).ToString()), expectedException: ExpectedException.ConfigurationErrorsException(substringExpected: "initialize", inner: typeof(ConfigurationErrorsException))));

            // certificate validator *40
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.Custom, cert: new AlwaysSucceedCertificateValidator()));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 2147483647));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(name: @"http://AllItemsSet/nameClaim"));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(role: @"http://AllItemsSet/roleClaim"));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(cert: new AlwaysSucceedCertificateValidator(), expectedException: ExpectedException.ConfigurationErrorsException("Jwt10619")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(clock: 15));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(name: @"http://AllItemsSet/nameClaim", role: @"http://AllItemsSet/roleClaim"));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(cert: new AlwaysSucceedCertificateValidator(), clock: 15, expectedException: ExpectedException.ConfigurationErrorsException("Jwt10619")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000, name: @"http://AllItemsSet/nameClaim", role: @"http://AllItemsSet/roleClaim", clock: 15));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000, name: @"http://AllItemsSet/nameClaim", role: @"http://AllItemsSet/roleClaim", clock: 15, cert: new AlwaysSucceedCertificateValidator(), certMode: X509CertificateValidationMode.Custom));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(tokenSize: 1000, name: @"http://AllItemsSet/nameClaim", role: @"http://AllItemsSet/roleClaim", clock: 15, cert: new AlwaysSucceedCertificateValidator(), expectedException: ExpectedException.ConfigurationErrorsException("Jwt10619")));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(role: @"http://AllItemsSet/roleClaim", cert: new AlwaysSucceedCertificateValidator(), clock: 15, certMode: X509CertificateValidationMode.Custom));
            RequirementVariations.Add(new ExpectedJwtSecurityTokenRequirement(certMode: X509CertificateValidationMode.PeerTrust, cert: new AlwaysSucceedCertificateValidator(), expectedException: ExpectedException.ConfigurationErrorsException("Jwt10619")));
        }

        public static ExpectedJwtSecurityTokenRequirement Variation(string variation)
        {
            if (RequirementVariations == null)
            {
                BuildExpectedRequirements();
            }

            return RequirementVariations[Convert.ToInt32(variation)];
        }

        //public static JwtHandlerConfigVariation BuildVariation( Int32 variation )
        //{
        //    return new JwtHandlerConfigVariation()
        //    {
        //        ExpectedSecurityTokenHandler = new JwtSecurityTokenHandler(),
        //        ExpectedJwtSecurityTokenRequirement = RequirementVariations[variation],
        //    };
        //}
    }

    [TestClass]
    public class JwtSecurityTokenHandlerConfigTest : ConfigurationTest
    {
        static Dictionary<string, string> _testCases = new Dictionary<string, string>();

        public static string ElementValue(string element, string value, string attributeValue = Attributes.Value, int count = 1)
        {
            string attributePart = string.Empty;
            string postfix = string.Empty;
            for (int i = 0; i < count; i++)
            {
                attributePart += attributeValue + (i == 0 ? string.Empty : i.ToString()) + "='" + value + "' ";
            }

            return "<" + element + " " + attributePart + " />";
        }

        //public static string ElementValue( string element, string value, string attributeValue = Attributes.Value ) { return "<" + element + " " + attributeValue + "='" + value + "' />"; }
        public static string ElementValueMultipleAttributes(string element, string value, string value2) { return "<" + element + " " + Attributes.Value + "='" + value + " " + Attributes.Value + "='" + value2 + "' />"; }
        public static string Attribute(string attribute, string value) { return attribute + "='" + value + "'"; }



        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public JwtSecurityTokenHandlerConfigTest()
        {
        }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider(TestContext);
        }

        /// <summary>
        /// The test context that is set by Visual Studio and TAEF - need to keep this exact signature
        /// </summary>
        public TestContext TestContext { get; set; }

        protected override string GetConfiguration(string variationId)
        {
            ExpectedJwtSecurityTokenRequirement variation = JwtHandlerConfigVariation.Variation(variationId);
            string config = @"<system.identityModel><identityConfiguration><securityTokenHandlers>"
                            + variation.Config
                            + @"</securityTokenHandlers></identityConfiguration></system.identityModel>";

            Console.WriteLine(string.Format("\n===================================\nTesting variation: '{0}'\nConfig:\n{1}", variationId, config));

            return config;
        }

        protected override void ValidateTestCase(string variationId)
        {
            ExpectedJwtSecurityTokenRequirement variation = JwtHandlerConfigVariation.Variation(variationId);
            try
            {
                IdentityConfiguration identityConfig = new IdentityConfiguration(IdentityConfiguration.DefaultServiceName);
                variation.ExpectedException.ProcessNoException();
                VerifyConfig(identityConfig, variation);
            }
            catch (Exception ex)
            {
                try
                {
                    variation.ExpectedException.ProcessException(ex);
                }
                catch (Exception innerException)
                {
                    Assert.Fail("\nConfig case failed:\n'{0}'\nConfig:\n'{1}'\nException:\n'{2}'.", variationId, variation.Config, innerException.ToString());
                }
            }
        }

        private void VerifyConfig(IdentityConfiguration identityconfig, ExpectedJwtSecurityTokenRequirement variation)
        {
            JwtSecurityTokenHandler handler = identityconfig.SecurityTokenHandlers[typeof(JwtSecurityToken)] as JwtSecurityTokenHandler;
            Assert.IsFalse(!variation.AsExpected(handler.JwtSecurityTokenRequirement), "JwtSecurityTokenRequirement was not as expected");
        }

        [TestMethod]
        [TestProperty("TestCaseID", "1E62250E-9208-4917-8677-0C82EFE6823E")]
        [Description("JwtSecurityTokenHandler Configuration Tests")]
        public void JwtSecurityTokenHandler_ConfigTests()
        {
            JwtHandlerConfigVariation.BuildExpectedRequirements();
            for (int i = 39; i < JwtHandlerConfigVariation.RequirementVariations.Count; i++)
            {
                RunTestCase(i.ToString());
            }
        }
    }
}
