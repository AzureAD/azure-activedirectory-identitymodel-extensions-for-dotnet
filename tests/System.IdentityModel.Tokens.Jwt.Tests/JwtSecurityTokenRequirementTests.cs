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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;
using System.Xml;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class JwtSecurityTokenRequirementTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        { }

        [ClassCleanup]
        public static void ClassCleanup()
        { }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider(TestContext);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "32B4E6E2-E43C-430B-A5D5-449C3D296AEA")]
        [Description("Tests: Constructor")]
        public void JwtSecurityTokenRequirement_Constructor()
        {
            // This class is a bit thin, most of the tests are in JwtConfigTests, just added a couple of missed cases that are easy to code directly.

            // *** null param
            JwtSecurityTokenRequirement JwtSecurityTokenRequirement;
            ExpectedException expectedException = new ExpectedException(thrown: typeof(ArgumentNullException), id: "element");
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(null);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch(Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            // *** wrong namespace
            XmlDocument xmlDocument = new XmlDocument();
            expectedException = ExpectedException.Config(id: "Jwt10601");
            XmlElement xmlElement = new CustomXmlElement("prefix", "localName", "http://www.gotJwt.com", xmlDocument);
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(xmlElement);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            // *** unknown X509RevocationMode
            expectedException = ExpectedException.Config(id: "Jwt10606");
            xmlElement = new CustomXmlElement("prefix", "jwtSecurityTokenRequirement", "http://www.gotJwt.com", xmlDocument);
            xmlElement.Attributes.Append(new CustomXmlAttribute("prefix", "issuerCertificateRevocationMode", "http://www.gotJwt.com", xmlDocument)
            {
                Value = "UnKnown:issuerCertificateRevocationMode",
            });
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(xmlElement);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            // *** unknown ValidationMode
            expectedException = ExpectedException.Config(id: "Jwt10606");
            xmlElement = new CustomXmlElement("prefix", "jwtSecurityTokenRequirement", "http://www.gotJwt.com", xmlDocument);
            xmlElement.Attributes.Append(new CustomXmlAttribute("prefix", "issuerCertificateValidationMode", "http://www.gotJwt.com", xmlDocument)
            {
                Value = "UnKnown:issuerCertificateValidationMode",
            });
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(xmlElement);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            // *** unknown TrustedStoreLocation
            expectedException = ExpectedException.Config(id: "Jwt10606");
            xmlElement = new CustomXmlElement("prefix", "jwtSecurityTokenRequirement", "http://www.gotJwt.com", xmlDocument);
            xmlElement.Attributes.Append(new CustomXmlAttribute("prefix", "issuerCertificateTrustedStoreLocation", "http://www.gotJwt.com", xmlDocument)
            {
                Value = "UnKnown:issuerCertificateTrustedStoreLocation",
            });
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(xmlElement);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            // *** unbale to create type
            expectedException = ExpectedException.Config(id: "Jwt10613");
            xmlElement = new CustomXmlElement("prefix", "jwtSecurityTokenRequirement", "http://www.gotJwt.com", xmlDocument);
            xmlElement.Attributes.Append(new CustomXmlAttribute("prefix", "issuerCertificateValidator", "http://www.gotJwt.com", xmlDocument)
            {
                Value = "UnKnown:issuerCertificateValidatorType",
            });

            xmlElement.Attributes.Append(new CustomXmlAttribute("prefix", "issuerCertificateValidationMode", "http://www.gotJwt.com", xmlDocument)
            {
                Value = "Custom",
            });
            
            try
            {
                JwtSecurityTokenRequirement = new JwtSecurityTokenRequirement(xmlElement);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "D60F8E9A-319A-4693-BAAC-D713A05AB723")]
        [Description("Tests: Defaults")]
        public void JwtSecurityTokenRequirement_Defaults()
        {
            JwtSecurityTokenRequirement jwtSecurityTokenRequirement = new JwtSecurityTokenRequirement();
        }

    }

    public class CustomXmlElement : XmlElement
    {
        public CustomXmlElement(string prefix, string localName, string namespaceUri, XmlDocument doc)
            : base(prefix, localName, namespaceUri,doc)
        {    
        }
    }

    public class CustomXmlAttribute : XmlAttribute
    {
        public CustomXmlAttribute(string prefix, string localName, string namespaceUri, XmlDocument doc)
            : base(prefix, localName, namespaceUri, doc)
        {
        }
    }
}
