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
    public class SamlActionTestSet
    {
        public SamlAction Action { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAdviceTestSet
    {
        public SamlAdvice Advice { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAssertionTestSet
    {
        public SamlAssertion Assertion { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAudienceRestrictionConditionTestSet
    {
        public SamlAudienceRestrictionCondition AudienceRestrictionCondition { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAttributeTestSet
    {
        public SamlAttribute Attribute { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAttributeStatementTestSet
    {
        public SamlAttributeStatement AttributeStatement { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAuthenticationStatementTestSet
    {
        public SamlAuthenticationStatement AuthenticationStatement { get; set; }
        public string Xml { get; set; }
    }

    public class SamlAuthorizationDecisionStatementTestSet
    {
        public SamlAuthorizationDecisionStatement AuthorizationDecision { get; set; }
        public string Xml { get; set; }
    }

    public class SamlConditionsTestSet
    {
        public SamlConditions Conditions { get; set; }
        public string Xml { get; set; }
    }

    public class SamlEvidenceTestSet
    {
        public SamlEvidence Evidence { get; set; }
        public string Xml { get; set; }
    }

    public class SamlSubjectTestSet
    {
        public SamlSubject Subject { get; set; }
        public string Xml { get; set; }
    }
#endregion

    public class TransformTestSet : XmlTestSet
    {
        private static string DSigNS { get => "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""; }

        private static string DSigPrefix { get => XmlSignatureConstants.Prefix + ":"; }

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

        public static KeyInfoTestSet MalformedCertificate
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        CertificateData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD",
                        Kid = "6B740DD01652EECE2737E05DAE36C5D18FCB74C3"
                    },
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
                return new KeyInfoTestSet
                {
                    KeyInfo = Default.KeyInfo,
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
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        IssuerName = "CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP",
                        Kid = "12345678",
                        SerialNumber = "12345678",
                    },
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
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        Kid = "31d97bd7",
                        SKI = "31d97bd7"
                    },
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
                var keyinfo = new KeyInfo
                {
                    Kid = "X509SubjectName",
                    SubjectName = "X509SubjectName"
                };

                return new KeyInfoTestSet
                {
                    KeyInfo = keyinfo,
                    TestId = nameof(SingleSubjectName),
                    Xml = XmlGenerator.Generate(keyinfo),
                };
            }
        }

        public static KeyInfoTestSet WithWhitespace
        {
            get
            {
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        CertificateData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD",
                        Kid = "6B740DD01652EECE2737E05DAE36C5D18FCB74C3"
                    },
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
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        CertificateData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD",
                        Kid = "6B740DD01652EECE2737E05DAE36C5D18FCB74C3"
                    },
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
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        CertificateData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD",
                        IssuerName = "CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP",
                        Kid = "X509SubjectName",
                        RetrievalMethodUri = "http://RetrievalMethod",
                        SerialNumber = "12345678",
                        SKI = "31d97bd7",
                        SubjectName = "X509SubjectName",
                    },
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
                return new KeyInfoTestSet
                {
                    KeyInfo = new KeyInfo
                    {
                        CertificateData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD",
                        IssuerName = "CN=TAMURA Kent, OU=TRL, O=IBM, L=Yamato-shi, ST=Kanagawa, C=JP",
                        Kid = "X509SubjectName",
                        RetrievalMethodUri = "http://RetrievalMethod",
                        SerialNumber = "12345678",
                        SKI = "31d97bd7",
                        SubjectName = "X509SubjectName",
                    },
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
    }

    public class SamlSecurityTokenTestSet : XmlTestSet
    {
        public SamlSecurityToken SamlSecurityToken
        {
            get;
            set;
        }
    }

    public class SignatureTestSet : XmlTestSet
    {
        public SecurityKey SecurityKey
        {
            get;
            set;
        } = ReferenceXml.DefaultAADSigningKey;

        public Signature Signature
        {
            get;
            set;
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
                return new SignatureTestSet
                {
                    Signature = Default.Signature,
                    TestId = nameof(UnknownDigestAlgorithm),
                    Xml = XmlGenerator.Generate(Default.Signature).Replace(SecurityAlgorithms.Sha256Digest, $"_{SecurityAlgorithms.Sha256Digest}" )
                };
            }
        }

        public static SignatureTestSet UnknownSignatureAlgorithm
        {
            get
            {
                return new SignatureTestSet
                {
                    Signature = Default.Signature,
                    TestId = nameof(UnknownSignatureAlgorithm),
                    Xml = XmlGenerator.Generate(Default.Signature).Replace(SecurityAlgorithms.RsaSha256Signature, $"_{SecurityAlgorithms.RsaSha256Signature}" )
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
                    var reference = Default.Reference;
                    reference.DigestValue = digestValue;
                    var signedInfo = Default.SignedInfo;
                    signedInfo.References.Add(reference);
                    _signedInfo_ReferenceDigestValueNotBase64 = new SignedInfoTestSet
                    {
                        SignedInfo = signedInfo,
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
                    Xml = XmlGenerator.Generate(signedInfo)
                };
            }
        }

        public static SignedInfoTestSet UnknownReferenceTransform
        {
            get
            {
                var signedInfo = Default.SignedInfo;
                var reference = Default.Reference;
                var unknownTransform = "_http://www.w3.org/2000/09/xmldsig#enveloped-signature";
                reference.Transforms.Clear();
                reference.Transforms.Add(unknownTransform);
                reference.Transforms.Add(SecurityAlgorithms.Sha256Digest);
                signedInfo.References.Add(reference);
                return new SignedInfoTestSet
                {
                    SignedInfo = signedInfo,
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
                    Xml = XmlGenerator.Generate(Default.SignedInfo)
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