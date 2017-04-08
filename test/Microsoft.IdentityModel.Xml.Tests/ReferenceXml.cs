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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class RefernceXml
    {
        public static SecurityKey Saml2Token_Valid_SecurityKey
        {
            get
            {
                var certData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
                var aadCert = new X509Certificate2(Convert.FromBase64String(certData));
                return new X509SecurityKey(aadCert);
            }
        }

        public static string Saml2Token_Valid =
            @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue></Reference></SignedInfo><SignatureValue>NRV7REVbDRflg616G6gYg0fAGTEw8BhtyPzqaU+kPQI35S1vpgt12VlQ57PkY7Rs0Jucx9npno+bQVMKN2DNhhnzs9qoNY2V3TcdJCcwaMexinHoFXHA0+J6+vR3RWTXhX+iAnfudtKThqbh/mECRLrjyTdy6L+qNkP7sALCWrSVwJVRmzkTOUF8zG4AKY9dQziec94Zv4S7G3cFgj/i7ok2DfBi7AEMCu1lh3dsQAMDeCvt7binhIH2D2ad3iCfYyifDGJ2ncn9hIyxrEiBdS8hZzWijcLs6+HQhVaz9yhZL9u/ZxSRaisXClMdqrLFjUghJ82sVfgQdp7SF165+Q==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotBefore=""2017-03-20T15:47:31.957Z"" NotOnOrAfter=""2017-03-20T16:47:31.957Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-03-20T15:52:31.551Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>";

        public static string Saml2Token_Valid_Formated =
            @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
                <Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer>
                <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <SignedInfo>
                        <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                        <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                            <Reference URI=""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"">
                                <Transforms>
                                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                                    <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                                </Transforms>
                                <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                                <DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue>
                            </Reference>
                    </SignedInfo>
                    <SignatureValue>NRV7REVbDRflg616G6gYg0fAGTEw8BhtyPzqaU+kPQI35S1vpgt12VlQ57PkY7Rs0Jucx9npno+bQVMKN2DNhhnzs9qoNY2V3TcdJCcwaMexinHoFXHA0+J6+vR3RWTXhX+iAnfudtKThqbh/mECRLrjyTdy6L+qNkP7sALCWrSVwJVRmzkTOUF8zG4AKY9dQziec94Zv4S7G3cFgj/i7ok2DfBi7AEMCu1lh3dsQAMDeCvt7binhIH2D2ad3iCfYyifDGJ2ncn9hIyxrEiBdS8hZzWijcLs6+HQhVaz9yhZL9u/ZxSRaisXClMdqrLFjUghJ82sVfgQdp7SF165+Q==</SignatureValue>
                        <KeyInfo>
                            <X509Data>
                                <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                            </X509Data>
                        </KeyInfo>
                </Signature>
                <Subject>
                    <NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID>
                    <SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                </Subject>
                <Conditions NotBefore=""2017-03-20T15:47:31.957Z"" NotOnOrAfter=""2017-03-20T16:47:31.957Z"">
                    <AudienceRestriction>
                        <Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience>
                    </AudienceRestriction>
                </Conditions>
                <AttributeStatement>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid"">
                        <AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier"">
                        <AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"">
                        <AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"">
                        <AttributeValue>1</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"">
                        <AttributeValue>User</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname"">
                        <AttributeValue>User1</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider"">
                        <AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue>
                    </Attribute>
                </AttributeStatement>
                <AuthnStatement AuthnInstant=""2017-03-20T15:52:31.551Z"">
                    <AuthnContext>
                        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
                    </AuthnContext>
                </AuthnStatement>
            </Assertion>";

        public static string Saml2Token_Valid_SignatureNOTFormated =
            @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
                <Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer>
                <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue></Reference></SignedInfo><SignatureValue>NRV7REVbDRflg616G6gYg0fAGTEw8BhtyPzqaU+kPQI35S1vpgt12VlQ57PkY7Rs0Jucx9npno+bQVMKN2DNhhnzs9qoNY2V3TcdJCcwaMexinHoFXHA0+J6+vR3RWTXhX+iAnfudtKThqbh/mECRLrjyTdy6L+qNkP7sALCWrSVwJVRmzkTOUF8zG4AKY9dQziec94Zv4S7G3cFgj/i7ok2DfBi7AEMCu1lh3dsQAMDeCvt7binhIH2D2ad3iCfYyifDGJ2ncn9hIyxrEiBdS8hZzWijcLs6+HQhVaz9yhZL9u/ZxSRaisXClMdqrLFjUghJ82sVfgQdp7SF165+Q==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature>
                <Subject>
                    <NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID>
                    <SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                </Subject>
                <Conditions NotBefore=""2017-03-20T15:47:31.957Z"" NotOnOrAfter=""2017-03-20T16:47:31.957Z"">
                    <AudienceRestriction>
                        <Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience>
                    </AudienceRestriction>
                </Conditions>
                <AttributeStatement>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid"">
                        <AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier"">
                        <AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"">
                        <AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"">
                        <AttributeValue>1</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"">
                        <AttributeValue>User</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname"">
                        <AttributeValue>User1</AttributeValue>
                    </Attribute>
                    <Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider"">
                        <AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue>
                    </Attribute>
                </AttributeStatement>
                <AuthnStatement AuthnInstant=""2017-03-20T15:52:31.551Z"">
                    <AuthnContext>
                        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
                    </AuthnContext>
                </AuthnStatement>
            </Assertion>";

        #region SignInfo

        public static string SignInfo =
            @"<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"" >
                <CanonicalizationMethod Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                <SignatureMethod Algorithm = ""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                <Reference URI = ""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"">
                  <Transforms>
                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                    <Transform Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                  </Transforms>
                  <DigestMethod Algorithm = ""http://www.w3.org/2001/04/xmlenc#sha256"" />
                  <DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue>
                </Reference>
             </SignedInfo>";

        public static string SignInfoStartsWithWhiteSpace =
            @"    <SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"" >
                <CanonicalizationMethod Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                <SignatureMethod Algorithm = ""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                <Reference URI = ""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"">
                  <Transforms>
                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                    <Transform Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                  </Transforms>
                  <DigestMethod Algorithm = ""http://www.w3.org/2001/04/xmlenc#sha256"" />
                  <DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue>
                </Reference>
             </SignedInfo>";

        public static string SignedInfoCanonicalizationMethodMissing =
        @"<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"" >
                <_CanonicalizationMethod Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                <SignatureMethod Algorithm = ""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                <Reference URI = ""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"">
                  <Transforms>
                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                    <Transform Algorithm = ""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                  </Transforms>
                  <DigestMethod Algorithm = ""http://www.w3.org/2001/04/xmlenc#sha256"" />
                  <DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue>
                </Reference>
             </SignedInfo>";

        public static SignedInfo ExpectedSignedInfo
        {
            get
            {
                var signedInfo = new SignedInfo();
                signedInfo.CanonicalizationMethod = @"http://www.w3.org/2001/10/xml-exc-c14n#";
                signedInfo.SignatureAlgorithm = @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

                var reference = new Reference();
                reference.DigestAlgorithm = @"http://www.w3.org/2001/04/xmlenc#sha256";
                reference.Uri = "#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2";
                reference.AddTransform(new EnvelopedSignatureTransform());
                reference.AddTransform(new ExclusiveCanonicalizationTransform());

                signedInfo.AddReference(reference);

                return signedInfo;
            }            
        }

        #endregion
    }
}
