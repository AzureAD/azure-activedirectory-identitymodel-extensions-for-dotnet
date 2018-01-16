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
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Xml.XmlSignatureConstants;

namespace Microsoft.IdentityModel.Tests
{
    public class XmlTestSet
    {
        public string Xml
        {
            get;
            set;
        }

        public string TestId
        {
            get;
            set;
        }
    }

#region Saml
    public class SamlActionTestSet : XmlTestSet
    {
        public SamlAction Action { get; set; }
    }

    public class SamlAdviceTestSet : XmlTestSet
    {
        public SamlAdvice Advice { get; set; }
    }

    public class SamlAssertionTestSet : XmlTestSet
    {
        public SamlAssertion Assertion { get; set; }
    }

    public class SamlAudienceRestrictionConditionTestSet : XmlTestSet
    {
        public SamlAudienceRestrictionCondition AudienceRestrictionCondition { get; set; }
    }

    public class SamlAttributeTestSet : XmlTestSet
    {
        public SamlAttribute Attribute { get; set; }
    }

    public class SamlAttributeStatementTestSet : XmlTestSet
    {
        public SamlAttributeStatement AttributeStatement { get; set; }
    }

    public class SamlAuthenticationStatementTestSet : XmlTestSet
    {
        public SamlAuthenticationStatement AuthenticationStatement { get; set; }
    }

    public class SamlAuthorizationDecisionStatementTestSet : XmlTestSet
    {
        public SamlAuthorizationDecisionStatement AuthorizationDecision { get; set; }
    }

    public class SamlConditionsTestSet : XmlTestSet
    {
        public SamlConditions Conditions { get; set; }
    }

    public class SamlEvidenceTestSet : XmlTestSet
    {
        public SamlEvidence Evidence { get; set; }
    }

    public class SamlSubjectTestSet : XmlTestSet
    {
        public SamlSubject Subject { get; set; }
    }

    public class SamlTokenTestSet : XmlTestSet
    {
        public SecurityToken SecurityToken { get; set; }

        public IEnumerable<ClaimsIdentity> Identities { get; set; }
    }

    //public class SamlSecurityTokenTestSet : XmlTestSet
    //{
    //    public SamlSecurityToken SamlSecurityToken
    //    {
    //        get;
    //        set;
    //    }
    //}

    #endregion

    public class TransformTestSet : XmlTestSet
    {
        private static string DSigNS { get => "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""; }

        private static string DSigPrefix { get => XmlSignatureConstants.PreferredPrefix + ":"; }

        public string Transform
        {
            get;
            set;
        }

        public static TransformTestSet AlgorithmDefaultReferenceUri
        {
            get => new TransformTestSet
            {
                TestId = nameof(AlgorithmDefaultReferenceUri),
                Transform = Default.ReferenceUri,
                Xml = XmlGenerator.TransformXml("", "Algorithm", Default.ReferenceUri.ToString(), "")
            };
        }

        public static TransformTestSet AlgorithmNull
        {
            get => new TransformTestSet
            {
                TestId = nameof(AlgorithmNull),
                Xml = XmlGenerator.TransformXml("", "Algorithm", null, "")
            };
        }

        public static TransformTestSet Enveloped_AlgorithmMissing
        {
            get => new TransformTestSet
            {
                TestId = nameof(Enveloped_AlgorithmMissing),
                Xml = XmlGenerator.TransformXml("", "_Algorithm", SecurityAlgorithms.EnvelopedSignature, "")
            };
        }

        public static TransformTestSet Enveloped_Valid_WithPrefix
        {
            get => new TransformTestSet
            {
                Transform = SecurityAlgorithms.EnvelopedSignature,
                Xml = XmlGenerator.TransformXml(DSigPrefix, "Algorithm", SecurityAlgorithms.EnvelopedSignature, DSigNS)
            };
        }

        public static TransformTestSet Enveloped_Valid_WithoutPrefix
        {
            get => new TransformTestSet
            {
                Transform = SecurityAlgorithms.EnvelopedSignature,
                Xml = XmlGenerator.TransformXml("", "Algorithm", SecurityAlgorithms.EnvelopedSignature, DSigNS)
            };
        }

        public static TransformTestSet C14n_CanonicalizationMethod_WithComments
        {
            get => new TransformTestSet
            {
                TestId = nameof(C14n_CanonicalizationMethod_WithComments),
                Transform = SecurityAlgorithms.ExclusiveC14nWithComments,
                Xml = XmlGenerator.TransformXml(DSigPrefix, Elements.CanonicalizationMethod, "Algorithm", SecurityAlgorithms.ExclusiveC14nWithComments, DSigNS)
            };
        }

        public static TransformTestSet C14n_ElementNotValid
        {
            get => new TransformTestSet
            {
                TestId = nameof(C14n_ElementNotValid),
                Transform = SecurityAlgorithms.EnvelopedSignature,
                Xml = XmlGenerator.TransformXml(DSigPrefix, Elements.DigestMethod, "Algorithm", SecurityAlgorithms.EnvelopedSignature, DSigNS)
            };
        }

        public static TransformTestSet C14n_Transform_WithComments
        {
            get => new TransformTestSet
            {   TestId = nameof(C14n_Transform_WithComments),
                Transform = SecurityAlgorithms.ExclusiveC14nWithComments,
                Xml = XmlGenerator.TransformXml(DSigPrefix, Elements.Transform, "Algorithm", SecurityAlgorithms.ExclusiveC14nWithComments, DSigNS)
            };
        }

        public static TransformTestSet C14n_Transform_WithoutNS
        {
            get => new TransformTestSet
            {
                TestId = nameof(C14n_Transform_WithoutNS),
                Transform = SecurityAlgorithms.ExclusiveC14n,
                Xml = XmlGenerator.TransformXml("", Elements.Transform, "Algorithm", SecurityAlgorithms.ExclusiveC14n, "")
            };
        }
        public static TransformTestSet TransformNull
        {
            get => new TransformTestSet
            {
                TestId = nameof(TransformNull),
                Xml = XmlGenerator.TransformXml("", Elements.Transform, "Algorithm", null, "")
            };
        }
    }

    public class KeyInfoTestSet : XmlTestSet
    {
        public KeyInfo KeyInfo
        {
            get;
            set;
        }

        public static KeyInfoTestSet KeyInfoFullyPopulated
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")))
                {
                    IssuerSerial = new IssuerSerial("CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP", "12345678"),
                    SKI = "31d97bd7",
                    SubjectName = "X509SubjectName"
                };
                var keyInfo = new KeyInfo
                {
                    RetrievalMethodUri = "http://RetrievalMethod",
                    RSAKeyValue = new RSAKeyValue(
                            "rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==",
                            "AQAB"),
                    KeyName = "KeyName"
                };
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithAllElements),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <KeyName>KeyName</KeyName>
                                <RetrievalMethod URI = ""http://RetrievalMethod""/>
                                <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                    <X509IssuerSerial>
                                        <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                        <X509SerialNumber>12345678</X509SerialNumber>
                                    </X509IssuerSerial>
                                    <X509SKI>31d97bd7</X509SKI>
                                    <X509SubjectName>X509SubjectName</X509SubjectName>
                                </X509Data>
                                <KeyValue>
                                    <RSAKeyValue>
                                        <Modulus>rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==</Modulus>
                                        <Exponent>AQAB</Exponent>
                                    </RSAKeyValue>
                                </KeyValue>
                            </KeyInfo>"
                };
            }
        }
    
        public static KeyInfoTestSet MalformedCertificate
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")));
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(MalformedCertificate),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509Certificate>%%MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet MultipleCertificates
        {
            get
            {
                var data = new X509Data(new List<X509Certificate2> { new X509Certificate2(Convert.FromBase64String(Default.CertificateData)), new X509Certificate2(Convert.FromBase64String(Default.CertificateData)) } );
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(MultipleCertificates),
                    Xml = XmlGenerator.KeyInfoXml(
                        "http://www.w3.org/2000/09/xmldsig#",
                        new XmlEement("X509Data", new List<XmlEement>
                        {
                           new XmlEement("X509Certificate", Default.CertificateData),
                           new XmlEement("X509Certificate", Default.CertificateData)
                        }))
                };
            }
        }

        public static KeyInfoTestSet MultipleIssuerSerial
        {
            get
            {
                return new KeyInfoTestSet
                {
                    TestId = nameof(MultipleIssuerSerial),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                   <X509IssuerSerial>
                                     <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                     <X509SerialNumber>12345678</X509SerialNumber>
                                   </X509IssuerSerial>
                                   <X509IssuerSerial>
                                     <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                     <X509SerialNumber>12345678</X509SerialNumber>
                                   </X509IssuerSerial>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet MultipleSKI
        {
            get
            {
                return new KeyInfoTestSet
                {
                    TestId = nameof(MultipleSKI),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509SKI>31d97bd7</X509SKI>
                                    <X509SKI>31d97bd7</X509SKI>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet MultipleSubjectName
        {
            get
            {
                return new KeyInfoTestSet
                {
                    TestId = nameof(MultipleSubjectName),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509SubjectName>X509SubjectName</X509SubjectName>
                                    <X509SubjectName>X509SubjectName</X509SubjectName>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet SingleCertificate
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = Default.KeyInfo,
                    TestId = nameof(SingleCertificate),
                    Xml = XmlGenerator.Generate(Default.KeyInfo),
                };
            }
        }

        public static KeyInfoTestSet SingleIssuerSerial
        {
            get
            {
                var data = new X509Data { IssuerSerial = new IssuerSerial("CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP", "12345678") };
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(SingleIssuerSerial),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                   <X509IssuerSerial>
                                     <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                     <X509SerialNumber>12345678</X509SerialNumber>
                                   </X509IssuerSerial>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet SingleSKI
        {
            get
            {
                var data = new X509Data { SKI = "31d97bd7" };
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(SingleSKI),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509SKI>31d97bd7</X509SKI>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet SingleSubjectName
        {
            get
            {
                var data = new X509Data { SubjectName = "X509SubjectName" };
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);

                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(SingleSubjectName),
                    Xml = XmlGenerator.Generate(keyInfo),
                };
            }
        }

        public static KeyInfoTestSet MultipleX509Data
        {
            get
            {
                var data1 = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")));
                var data2 = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B")));
                            
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data1);
                keyInfo.X509Data.Add(data2);

                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithRSAKeyValue),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                </X509Data>
                                  <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WithRSAKeyValue
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")));
                var keyInfo = new KeyInfo()
                {
                    RSAKeyValue = new RSAKeyValue(
                            "rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==",
                            "AQAB")
                };
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithRSAKeyValue),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                </X509Data>
                                <KeyValue>
                                    <RSAKeyValue>
                                        <Modulus>rCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVw==</Modulus>
                                        <Exponent>AQAB</Exponent>
                                    </RSAKeyValue>
                                </KeyValue>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WithWhitespace
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")));
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithWhitespace),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">

                                <X509Data>

                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>

                                </X509Data>

                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WithUnknownX509DataElements
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")));
                var keyInfo = new KeyInfo();
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithUnknownX509DataElements),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <X509Data>
                                    <Unknown>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</Unknown>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WithAllElements
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")))
                {
                    IssuerSerial = new IssuerSerial("CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP", "12345678"),
                    SKI = "31d97bd7",
                    SubjectName = "X509SubjectName"
                };
                var keyInfo = new KeyInfo
                {
                    RetrievalMethodUri = "http://RetrievalMethod",
                };
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithAllElements),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <RetrievalMethod URI = ""http://RetrievalMethod"" >some info </RetrievalMethod>
                                <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                    <X509IssuerSerial>
                                        <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                        <X509SerialNumber>12345678</X509SerialNumber>
                                    </X509IssuerSerial>
                                    <X509SKI>31d97bd7</X509SKI>
                                    <X509SubjectName>X509SubjectName</X509SubjectName>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WithUnknownElements
        {
            get
            {
                var data = new X509Data(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD")))
                {
                    IssuerSerial = new IssuerSerial("CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP", "12345678"),
                    SKI = "31d97bd7",
                    SubjectName = "X509SubjectName"
                };
                var keyInfo = new KeyInfo
                {
                    RetrievalMethodUri = "http://RetrievalMethod",
                };
                keyInfo.X509Data.Add(data);
                return new KeyInfoTestSet
                {
                    KeyInfo = keyInfo,
                    TestId = nameof(WithUnknownElements),
                    Xml = @"<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                <UnknownElement>some data</UnknownElement>
                                <RetrievalMethod URI = ""http://RetrievalMethod"" >some info </RetrievalMethod>
                                <X509Data>
                                    <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                                    <X509IssuerSerial>
                                        <X509IssuerName>CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP</X509IssuerName>
                                        <X509SerialNumber>12345678</X509SerialNumber>
                                    </X509IssuerSerial>
                                    <X509SKI>31d97bd7</X509SKI>
                                    <X509SubjectName>X509SubjectName</X509SubjectName>
                                </X509Data>
                            </KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet WrongElement
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = Default.KeyInfo,
                    TestId = nameof(WithUnknownElements),
                    Xml = XmlGenerator.Generate(Default.KeyInfo).Replace("<KeyInfo", "<NotKeyInfo>").Replace("/KeyInfo>", "/NotKeyInfo>")
                };
            }
        }

        public static KeyInfoTestSet WrongNamespace
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = Default.KeyInfo,
                    TestId = nameof(WrongNamespace),
                    Xml = XmlGenerator.Generate(Default.KeyInfo).Replace(XmlSignatureConstants.Namespace, $"_{XmlSignatureConstants.Namespace}_")
                };
            }
        }

        public static KeyInfoTestSet KeyInfoEmpty
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo(),
                    TestId = nameof(KeyInfoEmpty),
                    Xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>"
                };
            }
        }

        public static KeyInfoTestSet X509DataEmpty
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo(),
                    TestId = nameof(X509DataEmpty),
                    Xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data/></KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet IssuerSerialEmpty
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo(),
                    TestId = nameof(IssuerSerialEmpty),
                    Xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509IssuerSerial/></X509Data></KeyInfo>"
                };
            }
        }

        public static KeyInfoTestSet RSAKeyValueEmpty
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo(),
                    TestId = nameof(RSAKeyValueEmpty),
                    Xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyValue><RSAKeyValue/></KeyValue></KeyInfo>"
                };
            }
        }
    }

    public class SignatureTestSet : XmlTestSet
    {
        public SecurityKey SecurityKey
        {
            get;
            set;
        } = KeyingMaterial.DefaultAADSigningKey;

        public Signature Signature
        {
            get;
            set;
        }

        public static SignatureTestSet EmptySignature
        {
            get
            {
                return new SignatureTestSet
                {
                    Signature = new Signature(),
                    TestId = nameof(EmptySignature),
                    Xml = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"></Signature>"
                };
            }
        }

        public static SignatureTestSet DefaultSignature
        {
            get
            {
                return new SignatureTestSet
                {
                    Signature = Default.Signature,
                    TestId = nameof(DefaultSignature),
                    Xml = XmlGenerator.Generate(Default.Signature)
                };
            }
        }

        public static SignatureTestSet UnknownDigestAlgorithm
        {
            get
            {
                var signature = Default.Signature;
                signature.SignedInfo.References[0].DigestMethod = $"_{SecurityAlgorithms.Sha256Digest}";

                return new SignatureTestSet
                {
                    Signature = signature,
                    TestId = nameof(UnknownDigestAlgorithm),
                    Xml = XmlGenerator.Generate(Default.Signature).Replace(SecurityAlgorithms.Sha256Digest, $"_{SecurityAlgorithms.Sha256Digest}" )
                };
            }
        }

        public static SignatureTestSet UnknownSignatureAlgorithm
        {
            get
            {
                var signature = Default.Signature;
                signature.SignedInfo.SignatureMethod = $"_{SecurityAlgorithms.RsaSha256Signature}";

                return new SignatureTestSet
                {
                    Signature = signature,
                    TestId = nameof(UnknownSignatureAlgorithm),
                    Xml = XmlGenerator.Generate(Default.Signature).Replace(SecurityAlgorithms.RsaSha256Signature, $"_{SecurityAlgorithms.RsaSha256Signature}" )
                };
            }
        }

        public static SignatureTestSet SignatureFullyPopulated
        { 
            get
            {
                var signatureBytes = XmlUtilities.GenerateSignatureBytes(SignedInfoTestSet.SignedInfoFullyPopulated.SignedInfo, Default.AsymmetricSigningKey);
                var signatureValue = Convert.ToBase64String(signatureBytes);

                var signature = new Signature()
                {
                    SignedInfo = SignedInfoTestSet.SignedInfoFullyPopulated.SignedInfo,
                    SignatureValue = signatureValue,
                    KeyInfo = KeyInfoTestSet.KeyInfoFullyPopulated.KeyInfo,
                    Id = "SignatureFullyPopulated"
                };

                return new SignatureTestSet
                {
                    Signature = signature,
                    TestId = nameof(SignatureFullyPopulated),
                    Xml = XmlGenerator.Generate(signature)
                };
            }
        }
    }

    public class SignedInfoTestSet : XmlTestSet
    {
        // if the test set should only be created once, use a static to control this.
        private static SignedInfoTestSet _signedInfo_ReferenceDigestValueNotBase64;

        public SignedInfo SignedInfo
        {
            get;
            set;
        }

        public static SignedInfoTestSet SignedInfoEmpty
        {
            get
            {
                return new SignedInfoTestSet
                {
                    SignedInfo = new SignedInfo(),
                    TestId = nameof(SignedInfoEmpty),
                    Xml = "<SignedInfo xmlns = \"http://www.w3.org/2000/09/xmldsig#\"/>"
                };
            }
        }

        public static SignedInfoTestSet StartsWithWhiteSpace
        {
            get
            {
                return new SignedInfoTestSet
                {
                    SignedInfo = Default.SignedInfo,
                    TestId = nameof(StartsWithWhiteSpace),
                    Xml = "       " + XmlGenerator.Generate(Default.SignedInfo)
                };
            }
        }

        public static SignedInfoTestSet CanonicalizationMethodMissing
        {
            get
            {
                return new SignedInfoTestSet
                {
                    TestId = nameof(CanonicalizationMethodMissing),
                    Xml = XmlGenerator.Generate(Default.SignedInfo).Replace("CanonicalizationMethod", "_CanonicalizationMethod")
                };
            }
        }
        public static SignedInfoTestSet ReferenceDigestValueNotBase64
        {
            get
            {
                if (_signedInfo_ReferenceDigestValueNotBase64 == null)
                {
                    var digestValue = Guid.NewGuid().ToString();
                    var reference = Default.ReferenceWithNullTokenStream;
                    reference.DigestValue = digestValue;
                    var signedInfo = Default.SignedInfo;
                    signedInfo.References.Clear();
                    signedInfo.References.Add(reference);
                    _signedInfo_ReferenceDigestValueNotBase64 = new SignedInfoTestSet
                    {
                        SignedInfo = signedInfo,
                        TestId = nameof(ReferenceDigestValueNotBase64),
                        Xml = XmlGenerator.SignedInfoXml(
                                XmlSignatureConstants.Namespace,
                                SecurityAlgorithms.ExclusiveC14n,
                                SecurityAlgorithms.RsaSha256Signature,
                                XmlGenerator.ReferenceXml(
                                    Default.ReferencePrefix + ":",
                                    Default.ReferenceId,
                                    Default.ReferenceType,
                                    Default.ReferenceUri,
                                    SecurityAlgorithms.EnvelopedSignature,
                                    SecurityAlgorithms.ExclusiveC14n,
                                    Default.ReferenceDigestMethod,
                                    digestValue))
                    };
                }

                return _signedInfo_ReferenceDigestValueNotBase64;
            }
        }

        public static SignedInfoTestSet ReferenceMissing
        {
            get
            {
                return new SignedInfoTestSet
                {
                    TestId = nameof(ReferenceMissing),
                    Xml = XmlGenerator.Generate(Default.SignedInfo).Replace("Reference", "_Reference")
                };
            }
        }

        public static SignedInfoTestSet NoTransforms
        {
            get
            {
                var signedInfo = Default.SignedInfo;
                signedInfo.References.Clear();
                signedInfo.References.Add(new Reference
                {
                    DigestMethod = SecurityAlgorithms.Sha256Digest,
                    DigestValue = Default.ReferenceDigestValue
                });

                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
                    TestId = nameof(NoTransforms),
                    Xml = XmlGenerator.Generate(signedInfo)
                };
            }
        }

        public static SignedInfoTestSet TwoReferences
        {
            get
            {
                var signedInfo = Default.SignedInfo;
                signedInfo.References.Add(new Reference
                {
                    DigestMethod = SecurityAlgorithms.Sha256Digest,
                    DigestValue = Default.ReferenceDigestValue
                });

                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
                    TestId = nameof(SignedInfoTestSet),
                    Xml = XmlGenerator.Generate(signedInfo)
                };
            }
        }

        public static SignedInfoTestSet TransformsMissing
        {
            get
            {
                var signedInfo = Default.SignedInfo;
                signedInfo.References.Clear();
                signedInfo.References.Add(new Reference
                {
                    DigestMethod = SecurityAlgorithms.Sha256Digest,
                    DigestValue = Default.ReferenceDigestValue
                });

                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
                    TestId = nameof(TransformsMissing),
                    Xml = XmlGenerator.Generate(signedInfo)
                };
            }
        }

        public static SignedInfoTestSet UnknownReferenceTransform
        {
            get
            {
                var signedInfo = Default.SignedInfo;
                var reference = Default.ReferenceWithNullTokenStream;
                var unknownTransform = "_http://www.w3.org/2000/09/xmldsig#enveloped-signature";
                reference.Transforms.Clear();
                reference.Transforms.Add(new EnvelopedSignatureTransform());
                reference.CanonicalizingTransfrom = new ExclusiveCanonicalizationTransform();
                signedInfo.References.Clear();
                signedInfo.References.Add(reference);
                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
                    TestId = nameof(UnknownReferenceTransform),
                    Xml = XmlGenerator.SignedInfoXml(
                            XmlSignatureConstants.Namespace,
                            SecurityAlgorithms.ExclusiveC14n,
                            SecurityAlgorithms.RsaSha256Signature,
                            XmlGenerator.ReferenceXml(
                                "ds:",
                                Default.ReferenceId,
                                Default.ReferenceType,
                                Default.ReferenceUri,
                                unknownTransform,
                                SecurityAlgorithms.ExclusiveC14n,
                                SecurityAlgorithms.Sha256Digest,
                                Default.ReferenceDigestValue))

                };
            }
        }

        public static SignedInfoTestSet MissingDigestMethod
        {
            get
            {
                return new SignedInfoTestSet
                {
                    TestId = nameof(MissingDigestMethod),
                    Xml = XmlGenerator.Generate(Default.SignedInfo).Replace("DigestMethod", "_DigestMethod")
                };
            }
        }

        public static SignedInfoTestSet MissingDigestValue
        {
            get
            {
                return new SignedInfoTestSet
                {
                    TestId = nameof(MissingDigestValue),
                    Xml = XmlGenerator.Generate(Default.SignedInfo).Replace("DigestValue", "_DigestValue")
                };
            }
        }

        public static SignedInfoTestSet Valid
        {
            get
            {
                return new SignedInfoTestSet
                {
                    SignedInfo = Default.SignedInfo,
                    TestId = nameof(Valid),
                    Xml = XmlGenerator.Generate(Default.SignedInfo)
                };
            }
        }

        public static SignedInfoTestSet SignedInfoFullyPopulated
        {
            get
            {
                var signedInfo = new SignedInfo(Default.ReferenceWithNullTokenStream)
                {
                    CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14n,
                    SignatureMethod = SecurityAlgorithms.RsaSha256Signature,
                    Id = "SignedInfoFullyPopulated"
                };

                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
                    TestId = nameof(SignedInfoFullyPopulated),
                    Xml = XmlGenerator.Generate(signedInfo)
                };
            }
        }
    }

    public class ReferenceTestSet : XmlTestSet
    {
        public Reference Reference
        {
            get;
            set;
        }

        public static ReferenceTestSet ReferenceEmpty
        {
            get
            {
                return new ReferenceTestSet
                {
                    Reference = new Reference(),
                    TestId = nameof(ReferenceEmpty),
                    Xml = "<ds:Reference Id=\"#abcdef\" Type=\"http://referenceType\" URI=\"http://referenceUri\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>"
                };
            }
        }

        public static ReferenceTestSet ReferenceWithNoUriIdWithPound
        {
            get
            {
                return new ReferenceTestSet
                {
                    Reference = new Reference() { Id = "#test", DigestMethod = Default.ReferenceDigestMethod, DigestValue = Default.ReferenceDigestValue },
                    TestId = nameof(ReferenceWithNoUriIdWithPound),
                    Xml = @"<Reference Id=""test"" URI=""#test"" xmlns=""http://www.w3.org/2000/09/xmldsig#""><Transforms/><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""/><DigestValue>rMea6HlsYH8lHYR11ouxgmyzb39HY1YE07J/1Dyqimw=</DigestValue></Reference>"
                };
            }
        }

        public static ReferenceTestSet ReferenceWithNoUriIdWithoutPound
        {
            get
            {
                return new ReferenceTestSet
                {
                    Reference = new Reference() { Id = "test", DigestMethod = Default.ReferenceDigestMethod, DigestValue = Default.ReferenceDigestValue },
                    TestId = nameof(ReferenceWithNoUriIdWithoutPound),
                    Xml = @"<Reference Id=""test"" URI=""#test"" xmlns=""http://www.w3.org/2000/09/xmldsig#""><Transforms/><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""/><DigestValue>rMea6HlsYH8lHYR11ouxgmyzb39HY1YE07J/1Dyqimw=</DigestValue></Reference>"
                };
            }
        }
    }

    public class TransformsTestSet : XmlTestSet
    {
        public IList<string> Transforms
        {
            get;
            set;
        }

        public static TransformsTestSet TransformsEmpty
        {
            get
            {
                return new TransformsTestSet
                {
                    Transforms = new List<string>(),
                    TestId = nameof(TransformsEmpty),
                    Xml = "<Transforms/>"
                };
            }
        }
    }
        
    public class WsFederationMessageTestSet : XmlTestSet
    {
        public WsFederationMessage WsFederationMessage
        {
            get;
            set;
        }
    }
}