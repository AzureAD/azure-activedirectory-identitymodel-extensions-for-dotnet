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
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;

namespace Microsoft.IdentityModel.Tests
{
    public class KeyInfoTestSets
    {
    }

    public class ReferenceXml
    {
        // TODO move this
        public static SecurityKey DefaultAADSigningKey
        {
            get
            {
                var certData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
                var aadCert = new X509Certificate2(Convert.FromBase64String(certData));
                return new X509SecurityKey(aadCert);
            }
        }

        #region EnvelopedSignatureReader / Writer

        public static string Saml2Token_TwoSignatures
        {
            get
            {
                return @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
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
            }
        }

        public static string Saml2Token_Valid_Formated
        {
            get
            {
                return @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
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
            }
        }

        public static string Saml2Token_Valid_SignatureNOTFormated
        {
            get
            {
                return @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
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
            }
        }

        public static string Saml2Token_Valid_Signed
        {
            get { return @"<Assertion ID = ""_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2"" IssueInstant=""2017-03-20T15:52:31.957Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_d60bd9ed-8aab-40c8-ba5f-f548c3401ae2""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>Ytfkc60mLe1Zgu7TBQpMv8nJ1SVxT0ZjsFHaFqSB2VI=</DigestValue></Reference></SignedInfo><SignatureValue>NRV7REVbDRflg616G6gYg0fAGTEw8BhtyPzqaU+kPQI35S1vpgt12VlQ57PkY7Rs0Jucx9npno+bQVMKN2DNhhnzs9qoNY2V3TcdJCcwaMexinHoFXHA0+J6+vR3RWTXhX+iAnfudtKThqbh/mECRLrjyTdy6L+qNkP7sALCWrSVwJVRmzkTOUF8zG4AKY9dQziec94Zv4S7G3cFgj/i7ok2DfBi7AEMCu1lh3dsQAMDeCvt7binhIH2D2ad3iCfYyifDGJ2ncn9hIyxrEiBdS8hZzWijcLs6+HQhVaz9yhZL9u/ZxSRaisXClMdqrLFjUghJ82sVfgQdp7SF165+Q==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotBefore=""2017-03-20T15:47:31.957Z"" NotOnOrAfter=""2017-03-20T16:47:31.957Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-03-20T15:52:31.551Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>"; }
        }

        #endregion

        #region EnvelopedSignatureTransform
        #endregion

        #region ExclusiveCanonicalizationTransform
        #endregion

        #region Saml

        #region SamlAction
        public static SamlActionTestSet SamlActionValueNull
        {
            get
            {
                return new SamlActionTestSet
                {
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, Default.SamlAction.Namespace.ToString(), null)
                };
            }
        }

        public static SamlActionTestSet SamlActionValueEmptyString
        {
            get
            {
                return new SamlActionTestSet
                {
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, Default.SamlAction.Namespace.ToString(), String.Empty)
                };
            }
        }

        public static SamlActionTestSet SamlActionNamespaceNull
        {
            get
            {
                return new SamlActionTestSet
                {
                    Action = Default.SamlAction,
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, null, Default.SamlAction.Value)
                };
            }
        }

        public static SamlActionTestSet SamlActionNamespaceEmptyString
        {
            get
            {
                return new SamlActionTestSet
                {
                    Action = Default.SamlAction,
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, string.Empty, Default.SamlAction.Value)
                };
            }
        }

        public static SamlActionTestSet SamlActionNamespaceNotAbsoluteUri
        {
            get
            {
                return new SamlActionTestSet
                {
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, "namespace", Default.SamlAction.Value)
                };
            }
        }

        public static SamlActionTestSet SamlActionValid
        {
            get
            {
                return new SamlActionTestSet
                {
                    Action = Default.SamlAction,
                    Xml = XmlGenerator.SamlActionXml(SamlConstants.Namespace, Default.SamlAction.Namespace.ToString(), Default.SamlAction.Value)
                };
            }
        }
        #endregion

        #region SamlAdvice
        public static SamlAdviceTestSet AdviceNoAssertionIDRefAndAssertion
        {
            get
            {
                return new SamlAdviceTestSet
                {
                    Advice = new SamlAdvice(),
                    Xml = XmlGenerator.SamlAdviceXml(null, null)
                };
            }
        }

        public static SamlAdviceTestSet AdviceWithAssertionIDRef
        {
            get
            {
                return new SamlAdviceTestSet
                {
                    Advice = new SamlAdvice(new string[] { Default.SamlAssertionID }),
                    Xml = XmlGenerator.SamlAdviceXml(XmlGenerator.SamlAssertionIDRefXml(Default.SamlAssertionID), null)
                };
            }
        }

        // TODO : Add this test case after complete SamlAssertion test cases
        public static SamlAdviceTestSet SamlAdviceWithAssertions
        {
            get
            {
                return new SamlAdviceTestSet
                {
                    Advice = new SamlAdvice(new List<SamlAssertion> { SamlAssertionNoSignature.Assertion }),
                    Xml = XmlGenerator.SamlAdviceXml(null, SamlAssertionNoSignature.Xml)
                };
            }
        }

        public static SamlAdviceTestSet SamlAdviceWithWrongElement
        {
            get
            {
                return new SamlAdviceTestSet
                {
                    Xml = XmlGenerator.SamlAdviceXml(SamlActionValid.Xml, null)
                };
            }
        }

        public static SamlAdviceTestSet SamlAdviceWithAssertionIDRefAndAssertions
        {
            get
            {
                return new SamlAdviceTestSet
                {
                    Advice = new SamlAdvice(new string[] { Default.SamlAssertionID }, new List<SamlAssertion> { SamlAssertionNoSignature.Assertion }),
                    Xml = XmlGenerator.SamlAdviceXml(XmlGenerator.SamlAssertionIDRefXml(Default.SamlAssertionID), SamlAssertionNoSignature.Xml)
                };
            }
        }
        #endregion

        #region SamlAssertion
        public static SamlAssertionTestSet SamlAssertionMissMajorVersion
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(null, Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionWrongMajorVersion
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(2), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMissMinorVersion
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), null, Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionWrongMinorVersion
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(2), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMissAssertionID
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), null, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionWrongAssertionID
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), "12345", Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMissIssuer
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, null, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMissIssuerInstant
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, null, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionNoCondition
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Assertion = new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), null, AdviceWithAssertionIDRef.Advice, new List<SamlStatement> { SamlAttributeStatementSingleAttribute.AttributeStatement }),
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, null, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionNoAdvice
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Assertion = new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), SamlConditionsSingleCondition.Conditions, null, new List<SamlStatement> { SamlAttributeStatementSingleAttribute.AttributeStatement }),
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, null, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMissStatement
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, null, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionWrongElementInStatementPlace
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlActionValid.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionNoSignature
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Assertion = new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), SamlConditionsSingleCondition.Conditions, AdviceWithAssertionIDRef.Advice, new List<SamlStatement> { SamlAttributeStatementSingleAttribute.AttributeStatement }),
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, SamlAttributeStatementSingleAttribute.Xml, null)
                };
            }
        }

        public static SamlAssertionTestSet SamlAssertionMultiStatements
        {
            get
            {
                return new SamlAssertionTestSet
                {
                    Assertion = new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), SamlConditionsSingleCondition.Conditions, AdviceWithAssertionIDRef.Advice, new List<SamlStatement> { SamlAttributeStatementSingleAttribute.AttributeStatement, SamlAttributeStatementSingleAttribute.AttributeStatement }),
                    Xml = XmlGenerator.SamlAssertionXml(Convert.ToString(SamlConstants.MajorVersionValue), Convert.ToString(SamlConstants.MinorVersionValue), Default.SamlAssertionID, Default.Issuer, Default.IssueInstant, SamlConditionsSingleCondition.Xml, AdviceWithAssertionIDRef.Xml, string.Concat(SamlAttributeStatementSingleAttribute.Xml, SamlAttributeStatementSingleAttribute.Xml), null)
                };
            }
        }
        #endregion

        #region SamlAttribute
        public static SamlAttributeTestSet SamlAttributeNameNull
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Xml = XmlGenerator.SamlAttributeXml(null, Default.AttributeNamespace, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeNameEmptyString
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Xml = XmlGenerator.SamlAttributeXml(string.Empty, Default.AttributeNamespace, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeNamespaceNull
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, null, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeNamespaceEmptyString
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, string.Empty, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeValueNull
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, Default.AttributeNamespace, null)
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeValueEmptyString
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Attribute = new SamlAttribute(Default.AttributeNamespace, Default.AttributeName, new string[] { string.Empty }),
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, Default.AttributeNamespace, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, string.Empty) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeSingleValue
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Attribute = Default.SamlAttributeSingleValue,
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, Default.AttributeNamespace, new List<string> { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country) })
                };
            }
        }

        public static SamlAttributeTestSet SamlAttributeMultiValue
        {
            get
            {
                return new SamlAttributeTestSet
                {
                    Attribute = Default.SamlAttributeMultiValue,
                    Xml = XmlGenerator.SamlAttributeXml(Default.AttributeName, Default.AttributeNamespace, new List<string>
                            { XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country),
                              XmlGenerator.SamlAttributeValueXml(SamlConstants.Namespace, Default.Country)  })
                };
            }
        }
        #endregion

        #region SamlAttributeStatement
        public static SamlAttributeStatementTestSet SamlAttributeStatementMissSubject
        {
            get
            {
                return new SamlAttributeStatementTestSet
                {
                    Xml = XmlGenerator.SamlAttributeStatementXml(null, SamlAttributeSingleValue.Xml)
                };
            }
        }

        public static SamlAttributeStatementTestSet SamlAttributeStatementMissAttribute
        {
            get
            {
                return new SamlAttributeStatementTestSet
                {
                    Xml = XmlGenerator.SamlAttributeStatementXml(SamlSubjectWithNameIdentifierAndConfirmation.Xml, null)
                };
            }
        }

        public static SamlAttributeStatementTestSet SamlAttributeStatementSingleAttribute
        {
            get
            {
                return new SamlAttributeStatementTestSet
                {
                    AttributeStatement = new SamlAttributeStatement(SamlSubjectWithNameIdentifierAndConfirmation.Subject, SamlAttributeSingleValue.Attribute),
                    Xml = XmlGenerator.SamlAttributeStatementXml(SamlSubjectWithNameIdentifierAndConfirmation.Xml, SamlAttributeSingleValue.Xml)
                };
            }
        }

        public static SamlAttributeStatementTestSet SamlAttributeStatementMultiAttributes
        {
            get
            {
                return new SamlAttributeStatementTestSet
                {
                    AttributeStatement = new SamlAttributeStatement(SamlSubjectWithNameIdentifierAndConfirmation.Subject,
                                new List<SamlAttribute> { SamlAttributeSingleValue.Attribute, SamlAttributeSingleValue.Attribute }),
                    Xml = XmlGenerator.SamlAttributeStatementXml(SamlSubjectWithNameIdentifierAndConfirmation.Xml, string.Concat(SamlAttributeSingleValue.Xml, SamlAttributeSingleValue.Xml))
                };
            }
        }
        #endregion

        #region SamlAuthenticationStatement
        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissSubject
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, null, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                        XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissMethod
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(null, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                        XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissInstant
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, null, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                        XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementNoSubjectLocality
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), null, null,
                                        new List<SamlAuthorityBinding> { new SamlAuthorityBinding(new System.Xml.XmlQualifiedName(Default.AuthorityKind), Default.Location, Default.Binding) }),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, null,
                                        XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementNoIPAddress
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), Default.DNSAddress, string.Empty,
                                        new List<SamlAuthorityBinding> { new SamlAuthorityBinding(new System.Xml.XmlQualifiedName(Default.AuthorityKind), Default.Location, Default.Binding) }),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(null, Default.DNSAddress),
                                XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementNoDNSAddress
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), string.Empty, Default.IPAddress,
                                        new List<SamlAuthorityBinding> { new SamlAuthorityBinding(new System.Xml.XmlQualifiedName(Default.AuthorityKind), Default.Location, Default.Binding) }),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, null),
                                XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementNoAuthorityBinding
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), Default.DNSAddress, Default.IPAddress, null),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress), null)
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissAuthorityKind
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                XmlGenerator.SamlAuthorityBindingXml(null, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissLocation
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, null, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMissBinding
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, null))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementValid
        {
            get
            {
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), Default.DNSAddress, Default.IPAddress,
                                        new List<SamlAuthorityBinding> { new SamlAuthorityBinding(new System.Xml.XmlQualifiedName(Default.AuthorityKind), Default.Location, Default.Binding) }),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding))
                };
            }
        }

        public static SamlAuthenticationStatementTestSet SamlAuthenticationStatementMultiBinding
        {
            get
            {
                string authorityBinding = XmlGenerator.SamlAuthorityBindingXml(Default.AuthorityKind, Default.Location, Default.Binding);
                SamlAuthorityBinding binding = new SamlAuthorityBinding(new System.Xml.XmlQualifiedName(Default.AuthorityKind), Default.Location, Default.Binding);
                return new SamlAuthenticationStatementTestSet
                {
                    AuthenticationStatement = new SamlAuthenticationStatement(SamlSubjectNameQualifierNull.Subject, Default.AuthenticationMethod, DateTime.Parse(Default.AuthenticationInstant), Default.DNSAddress, Default.IPAddress,
                                        new List<SamlAuthorityBinding> { binding, binding }),
                    Xml = XmlGenerator.SamlAuthenticationStatementXml(Default.AuthenticationMethod, Default.AuthenticationInstant, SamlSubjectNameQualifierNull.Xml, XmlGenerator.SamlSubjectLocalityXml(Default.IPAddress, Default.DNSAddress),
                                string.Concat(authorityBinding, authorityBinding))
                };
            }
        }
        #endregion

        #region SamlAudienceRestrictionCondition
        public static SamlAudienceRestrictionConditionTestSet SamlAudienceRestrictionConditionNoAudience
        {
            get
            {
                return new SamlAudienceRestrictionConditionTestSet
                {
                    Xml = XmlGenerator.SamlAudienceRestrictionConditionXml(new string[] { })
                };
            }
        }

        public static SamlAudienceRestrictionConditionTestSet SamlAudienceRestrictionConditionEmptyAudience
        {
            get
            {
                return new SamlAudienceRestrictionConditionTestSet
                {
                    Xml = XmlGenerator.SamlAudienceRestrictionConditionXml(new string[] { XmlGenerator.SamlAudienceXml(string.Empty) })
                };
            }
        }

        public static SamlAudienceRestrictionConditionTestSet SamlAudienceRestrictionConditionInvaidElement
        {
            get
            {
                return new SamlAudienceRestrictionConditionTestSet
                {
                    Xml = XmlGenerator.SamlAudienceRestrictionConditionXml(new string[] { XmlGenerator.SamlActionXml(null, null, null) })
                };
            }
        }

        public static SamlAudienceRestrictionConditionTestSet SamlAudienceRestrictionConditionSingleAudience
        {
            get
            {
                return new SamlAudienceRestrictionConditionTestSet
                {
                    AudienceRestrictionCondition = Default.SamlAudienceRestrictionConditionSingleAudience,
                    Xml = XmlGenerator.SamlAudienceRestrictionConditionXml(new string[] { XmlGenerator.SamlAudienceXml(Default.Audience) })
                };
            }
        }

        public static SamlAudienceRestrictionConditionTestSet SamlAudienceRestrictionConditionMultiAudience
        {
            get
            {
                var audiences = new List<string>();
                foreach (var audience in Default.Audiences)
                {
                    audiences.Add(XmlGenerator.SamlAudienceXml(audience));
                }

                return new SamlAudienceRestrictionConditionTestSet
                {
                    AudienceRestrictionCondition = Default.SamlAudienceRestrictionConditionMultiAudience,
                    Xml = XmlGenerator.SamlAudienceRestrictionConditionXml(audiences)
                };
            }
        }
        #endregion

        #region SamlAuthorizationDecisionStatement
        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionMissResource
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(null, Default.SamlAccessDecision.ToString(), SamlSubjectWithNameIdentifierAndConfirmation.Xml, SamlActionValid.Xml, SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionMissAccessDecision
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, null, SamlSubjectWithNameIdentifierAndConfirmation.Xml, SamlActionValid.Xml, SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionMissSubject
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, Default.SamlAccessDecision.ToString(), null, SamlActionValid.Xml, SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionMissAction
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, Default.SamlAccessDecision.ToString(), SamlSubjectWithNameIdentifierAndConfirmation.Xml, null, SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionNoEvidence
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    AuthorizationDecision = new SamlAuthorizationDecisionStatement(SamlSubjectWithNameIdentifierAndConfirmation.Subject, Default.SamlResource, Default.SamlAccessDecision, new List<SamlAction> { SamlActionValid.Action }),
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, Default.SamlAccessDecision.ToString(), SamlSubjectWithNameIdentifierAndConfirmation.Xml, SamlActionValid.Xml, null)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionSingleAction
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    AuthorizationDecision = new SamlAuthorizationDecisionStatement(SamlSubjectWithNameIdentifierAndConfirmation.Subject, Default.SamlResource, Default.SamlAccessDecision, new List<SamlAction> { SamlActionValid.Action }, SamlEvidenceWithAssertionIDRef.Evidence),
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, Default.SamlAccessDecision.ToString(), SamlSubjectWithNameIdentifierAndConfirmation.Xml, SamlActionValid.Xml, SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }

        public static SamlAuthorizationDecisionStatementTestSet SamlAuthorizationDecisionMultiActions
        {
            get
            {
                return new SamlAuthorizationDecisionStatementTestSet
                {
                    AuthorizationDecision = new SamlAuthorizationDecisionStatement(SamlSubjectWithNameIdentifierAndConfirmation.Subject, Default.SamlResource, Default.SamlAccessDecision, new List<SamlAction> { SamlActionValid.Action, SamlActionValid.Action }, SamlEvidenceWithAssertionIDRef.Evidence),
                    Xml = XmlGenerator.SamlAuthorizationDecisionStatementXml(Default.SamlResource, Default.SamlAccessDecision.ToString(), SamlSubjectWithNameIdentifierAndConfirmation.Xml, string.Concat(SamlActionValid.Xml, SamlActionValid.Xml), SamlEvidenceWithAssertionIDRef.Xml)
                };
            }
        }
        #endregion

        #region SamlConditions
        public static SamlConditionsTestSet SamlConditionsNoNbf
        {
            get
            {
                return new SamlConditionsTestSet
                {
                    Conditions = new SamlConditions(DateTimeUtil.GetMinValue(DateTimeKind.Utc), Default.NotOnOrAfter, new List<SamlCondition> { Default.SamlAudienceRestrictionConditionSingleAudience }),
                    Xml = XmlGenerator.SamlConditionsXml(null, Default.NotOnOrAfterString, new List<string> { SamlAudienceRestrictionConditionSingleAudience.Xml })
                };
            }
        }

        public static SamlConditionsTestSet SamlConditionsNoNotOnOrAfter
        {
            get
            {
                return new SamlConditionsTestSet
                {
                    Conditions = new SamlConditions(Default.NotBefore, DateTimeUtil.GetMaxValue(DateTimeKind.Utc), new List<SamlCondition> { Default.SamlAudienceRestrictionConditionSingleAudience }),
                    Xml = XmlGenerator.SamlConditionsXml(Default.NotBeforeString, null, new List<string> { SamlAudienceRestrictionConditionSingleAudience.Xml })
                };
            }
        }

        public static SamlConditionsTestSet SamlConditionsNoCondition
        {
            get
            {
                return new SamlConditionsTestSet
                {
                    Conditions = new SamlConditions(DateTimeUtil.GetMinValue(DateTimeKind.Utc), DateTimeUtil.GetMaxValue(DateTimeKind.Utc)),
                    Xml = XmlGenerator.SamlConditionsXml(null, null, null)
                };
            }
        }

        public static SamlConditionsTestSet SamlConditionsSingleCondition
        {
            get
            {
                return new SamlConditionsTestSet
                {
                    Conditions = Default.SamlConditionsSingleCondition,
                    Xml = XmlGenerator.SamlConditionsXml(Default.NotBeforeString, Default.NotOnOrAfterString, new List<string> { SamlAudienceRestrictionConditionSingleAudience.Xml })
                };
            }
        }

        public static SamlConditionsTestSet SamlConditionsMultiCondition
        {
            get
            {
                return new SamlConditionsTestSet
                {
                    Conditions = new SamlConditions(Default.NotBefore, Default.NotOnOrAfter, new List<SamlCondition>
                        { Default.SamlAudienceRestrictionConditionSingleAudience,
                          Default.SamlAudienceRestrictionConditionMultiAudience }),
                    Xml = XmlGenerator.SamlConditionsXml(Default.NotBeforeString, Default.NotOnOrAfterString,
                            new List<string> { SamlAudienceRestrictionConditionSingleAudience.Xml, SamlAudienceRestrictionConditionMultiAudience.Xml })
                };
            }
        }
        #endregion

        #region SamlEvdience
        public static SamlEvidenceTestSet SamlEvidenceMissAssertionIDRefAndAssertion
        {
            get
            {
                return new SamlEvidenceTestSet
                {
                    Xml = XmlGenerator.SamlEvidenceXml(null, null)
                };
            }
        }

        public static SamlEvidenceTestSet SamlEvidenceWithAssertionIDRef
        {
            get
            {
                return new SamlEvidenceTestSet
                {
                    Evidence = new SamlEvidence(new string[] { Default.SamlAssertionID }),
                    Xml = XmlGenerator.SamlEvidenceXml(XmlGenerator.SamlAssertionIDRefXml(Default.SamlAssertionID), null)
                };
            }
        }

        // TODO : Add this test case after complete SamlAssertion test cases
        public static SamlEvidenceTestSet SamlEvidenceWithAssertions
        {
            get
            {
                return new SamlEvidenceTestSet
                {
                    Evidence = new SamlEvidence(new List<SamlAssertion> { SamlAssertionNoSignature.Assertion }),
                    Xml = XmlGenerator.SamlEvidenceXml(null, SamlAssertionNoSignature.Xml)
                };
            }
        }

        public static SamlEvidenceTestSet SamlEvidenceWithWrongElement
        {
            get
            {
                return new SamlEvidenceTestSet
                {
                    Xml = XmlGenerator.SamlEvidenceXml(SamlActionValid.Xml, null)
                };
            }
        }

        public static SamlEvidenceTestSet SamlEvidenceWithAssertionIDRefAndAssertions
        {
            get
            {
                return new SamlEvidenceTestSet
                {
                    Evidence = new SamlEvidence(new string[] { Default.SamlAssertionID }, new List<SamlAssertion> { SamlAssertionNoSignature.Assertion }),
                    Xml = XmlGenerator.SamlEvidenceXml(XmlGenerator.SamlAssertionIDRefXml(Default.SamlAssertionID), SamlAssertionNoSignature.Xml)
                };
            }
        }
        #endregion

        #region SamlSubject
        public static SamlSubjectTestSet SamlSubjectNameIdentifierNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(null, null, null, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(null, XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) },
                                        Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectNameQualifierNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, null, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(null, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectNameQualifierEmptyString
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, string.Empty, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(string.Empty, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectFormatNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(null, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, null, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectFormatEmptystring
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(string.Empty, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, string.Empty, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectNameNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, null),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectNameEmptyString
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, string.Empty),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectConfirmationDataNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, null),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, null))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectConfirmationDataEmptyString
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, string.Empty),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, string.Empty))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectConfirmationMethodNull
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(null, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectConfirmationMethodEmptyString
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject), 
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(string.Empty) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectWithNameIdentifierAndConfirmation
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject), 
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }

        public static SamlSubjectTestSet SamlSubjectWithMultiConfirmationMethods
        {
            get
            {
                return new SamlSubjectTestSet
                {
                    Subject = new SamlSubject(Default.NameIdentifierFormat, Default.NameQualifier, Default.Subject, new List<string> { Default.SamlConfirmationMethod, Default.SamlConfirmationMethod }, Default.SamlConfirmationData),
                    Xml = XmlGenerator.SamlSubjectXml(XmlGenerator.SamlNameIdentifierXml(Default.NameQualifier, Default.NameIdentifierFormat, Default.Subject),
                                XmlGenerator.SamlSubjectConfirmationXml(new List<string> { XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod), XmlGenerator.SamlConfirmationMethodXml(Default.SamlConfirmationMethod) }, Default.SamlConfirmationData))
                };
            }
        }
        #endregion

        #endregion

        #region Signature

        #endregion

        #region SignInfo

        #endregion

        #region Wresult

        public static string WResult_Saml2_Valid
        {
            get
            {
                return @"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust""><t:Lifetime><wsu:Created xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T16:11:17.348Z</wsu:Created><wsu:Expires xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T17:11:17.348Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy""><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><Assertion ID=""_edc15efd-1117-4bf9-89da-28b1663fb890"" IssueInstant=""2017-04-23T16:16:17.348Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_edc15efd-1117-4bf9-89da-28b1663fb890""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>DO8QQoO629ApWPV3LiY2epQSv+I82iChybeRrXbhgtw=</DigestValue></Reference></SignedInfo><SignatureValue>O8JNyVKm9I7kMqlsaBgLCNwHA0qdXv34YHBVfg217lgeKkMC5taLU/EH7UeeMtapU6zMafcYoCH+Bp9zoqDpflgs78Hkjgn/dEUtjPFn7211VXClcTNqk+yhqXWtu6SKrabeIhKCKtoMA9lUAB4D6ABesb6MpwbM/ULq7T16tycZ3X//iXHeOiMwNiUAePYF22fmgrqRSDRHyLPtiLskP4UMksWJBrXUV96e9EU9aEciCvYpzMDv/VFUOCLiEkBqCdAtPVwVun+5eRk9zEh6qscWi0kAgFl3W3JhugcTTuGQYHXYVIHxbd5O33MwFIMUOmGrI1EXuk+cHIq2KUtSLg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotBefore=""2017-04-23T16:11:17.348Z"" NotOnOrAfter=""2017-04-23T17:11:17.348Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/claims/authnmethodsreferences""><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-04-23T16:16:17.270Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></t:RequestedSecurityToken><t:RequestedAttachedReference><SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier></SecurityTokenReference></t:RequestedAttachedReference><t:RequestedUnattachedReference><SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier></SecurityTokenReference></t:RequestedUnattachedReference><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
            }
        }

        public static string WResult_Saml2_Valid_Formated
        {
            get
            {
                return @"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
                            <t:Lifetime>
                                <wsu:Created xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T16:11:17.348Z</wsu:Created>
                                <wsu:Expires xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T17:11:17.348Z</wsu:Expires>
                            </t:Lifetime>
                            <wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy"">
                                <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                                <wsa:Address>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</wsa:Address></wsa:EndpointReference>
                            </wsp:AppliesTo>
                            <t:RequestedSecurityToken>
                                <Assertion ID=""_edc15efd-1117-4bf9-89da-28b1663fb890"" IssueInstant=""2017-04-23T16:16:17.348Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
                                    <Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer>
                                    <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                                        <SignedInfo>
                                            <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                                            <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                                            <Reference URI=""#_edc15efd-1117-4bf9-89da-28b1663fb890"">
                                                <Transforms>
                                                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                                                    <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                                                </Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                                                <DigestValue>DO8QQoO629ApWPV3LiY2epQSv+I82iChybeRrXbhgtw=</DigestValue>
                                            </Reference>
                                        </SignedInfo>
                                        <SignatureValue>O8JNyVKm9I7kMqlsaBgLCNwHA0qdXv34YHBVfg217lgeKkMC5taLU/EH7UeeMtapU6zMafcYoCH+Bp9zoqDpflgs78Hkjgn/dEUtjPFn7211VXClcTNqk+yhqXWtu6SKrabeIhKCKtoMA9lUAB4D6ABesb6MpwbM/ULq7T16tycZ3X//iXHeOiMwNiUAePYF22fmgrqRSDRHyLPtiLskP4UMksWJBrXUV96e9EU9aEciCvYpzMDv/VFUOCLiEkBqCdAtPVwVun+5eRk9zEh6qscWi0kAgFl3W3JhugcTTuGQYHXYVIHxbd5O33MwFIMUOmGrI1EXuk+cHIq2KUtSLg==</SignatureValue>
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
                                    <Conditions NotBefore=""2017-04-23T16:11:17.348Z"" NotOnOrAfter=""2017-04-23T17:11:17.348Z"">
                                        <AudienceRestriction>
                                            <Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience>
                                        </AudienceRestriction>
                                    </Conditions>
                                    <AttributeStatement>
                                        <Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute>
                                        <Attribute Name=""http://schemas.microsoft.com/claims/authnmethodsreferences""><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute>
                                    </AttributeStatement>
                                    <AuthnStatement AuthnInstant=""2017-04-23T16:16:17.270Z"">
                                        <AuthnContext>
                                            <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
                                        </AuthnContext>
                                    </AuthnStatement>
                                </Assertion>
                            </t:RequestedSecurityToken>
                            <t:RequestedAttachedReference>
                                <SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
                                    <KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
                                </SecurityTokenReference>
                            </t:RequestedAttachedReference>
                            <t:RequestedUnattachedReference>
                                <SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
                                    <KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
                                </SecurityTokenReference>
                            </t:RequestedUnattachedReference>
                            <t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType>
                            <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
                            <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
                        </t:RequestSecurityTokenResponse>";
            }
        }

        public static string WResult_Saml2_Valid_With_Spaces
        {
            get
            {
                return @"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
                             
                             <t:Lifetime><wsu:Created xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T16:11:17.348Z</wsu:Created><wsu:Expires xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T17:11:17.348Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy""><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>
                             
                             <t:RequestedSecurityToken><Assertion ID=""_edc15efd-1117-4bf9-89da-28b1663fb890"" IssueInstant=""2017-04-23T16:16:17.348Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_edc15efd-1117-4bf9-89da-28b1663fb890""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>DO8QQoO629ApWPV3LiY2epQSv+I82iChybeRrXbhgtw=</DigestValue></Reference></SignedInfo><SignatureValue>O8JNyVKm9I7kMqlsaBgLCNwHA0qdXv34YHBVfg217lgeKkMC5taLU/EH7UeeMtapU6zMafcYoCH+Bp9zoqDpflgs78Hkjgn/dEUtjPFn7211VXClcTNqk+yhqXWtu6SKrabeIhKCKtoMA9lUAB4D6ABesb6MpwbM/ULq7T16tycZ3X//iXHeOiMwNiUAePYF22fmgrqRSDRHyLPtiLskP4UMksWJBrXUV96e9EU9aEciCvYpzMDv/VFUOCLiEkBqCdAtPVwVun+5eRk9zEh6qscWi0kAgFl3W3JhugcTTuGQYHXYVIHxbd5O33MwFIMUOmGrI1EXuk+cHIq2KUtSLg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotBefore=""2017-04-23T16:11:17.348Z"" NotOnOrAfter=""2017-04-23T17:11:17.348Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/claims/authnmethodsreferences""><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-04-23T16:16:17.270Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></t:RequestedSecurityToken><t:RequestedAttachedReference><SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier></SecurityTokenReference></t:RequestedAttachedReference><t:RequestedUnattachedReference><SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier></SecurityTokenReference></t:RequestedUnattachedReference><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>

                         </t:RequestSecurityTokenResponse>";
            }
        }

        public static string WResult_Saml2_Missing_RequestedSecurityTokenResponse
        {
            get
            {
                return @"<t:_RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust""></t:_RequestSecurityTokenResponse>";
            }
        }

        public static string WResult_Saml2_Missing_RequestedSecurityToken
        {
            get
            {
                return @"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
                            <t:_RequestedSecurityToken></t:_RequestedSecurityToken>
                         </t:RequestSecurityTokenResponse>";
            }
        }

        public static string WaSignIn_Valid
        {
            get
            {
                return @"wa=wsignin1.0&wresult=%3Ct%3ARequestSecurityTokenResponse+xmlns%3At%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F02%2Ftrust%22%3E%3Ct%3ALifetime%3E%3Cwsu%3ACreated+xmlns%3Awsu%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-utility-1.0.xsd%22%3E2017-04-23T17%3A40%3A36.882Z%3C%2Fwsu%3ACreated%3E%3Cwsu%3AExpires+xmlns%3Awsu%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-utility-1.0.xsd%22%3E2017-04-23T18%3A40%3A36.882Z%3C%2Fwsu%3AExpires%3E%3C%2Ft%3ALifetime%3E%3Cwsp%3AAppliesTo+xmlns%3Awsp%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2004%2F09%2Fpolicy%22%3E%3Cwsa%3AEndpointReference+xmlns%3Awsa%3D%22http%3A%2F%2Fwww.w3.org%2F2005%2F08%2Faddressing%22%3E%3Cwsa%3AAddress%3Espn%3Afe78e0b4-6fe7-47e6-812c-fb75cee266a4%3C%2Fwsa%3AAddress%3E%3C%2Fwsa%3AEndpointReference%3E%3C%2Fwsp%3AAppliesTo%3E%3Ct%3ARequestedSecurityToken%3E%3CAssertion+ID%3D%22_710d4516-27ac-4547-816d-3947aeea6edf%22+IssueInstant%3D%222017-04-23T17%3A45%3A36.882Z%22+Version%3D%222.0%22+xmlns%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Aassertion%22%3E%3CIssuer%3Ehttps%3A%2F%2Fsts.windows.net%2Fadd29489-7269-41f4-8841-b63c95564420%2F%3C%2FIssuer%3E%3CSignature+xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23%22%3E%3CSignedInfo%3E%3CCanonicalizationMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F10%2Fxml-exc-c14n%23%22+%2F%3E%3CSignatureMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256%22+%2F%3E%3CReference+URI%3D%22%23_710d4516-27ac-4547-816d-3947aeea6edf%22%3E%3CTransforms%3E%3CTransform+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23enveloped-signature%22+%2F%3E%3CTransform+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F10%2Fxml-exc-c14n%23%22+%2F%3E%3C%2FTransforms%3E%3CDigestMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmlenc%23sha256%22+%2F%3E%3CDigestValue%3Ekv1eRd%2BMFFaevhwOeeJa5BLkLRV3tFB5QKVD8JBOgMg%3D%3C%2FDigestValue%3E%3C%2FReference%3E%3C%2FSignedInfo%3E%3CSignatureValue%3EABAzMsMPGlKCA0HcmAAiCFwMZr0gtKMUQpRUTCX8YaLAIxOgIW3ZBMTwPHKa2K2lp1Tk97oQBE3S%2Bfg7TKriP1bZB8bdPpfu4GxeeYQteWT7dD%2FJPy1SYCMiRMSsNO4T3O6Keaci1pzwIxzrH8S5s7gzBFPgljf5mHBtZrCTQIK7Ng%2Fnk%2BSpea3RXew05yAQX%2B14Eq6IGPIBsFJidjLqyoslK4OZMNtHLF443AfLs4Ltwfaf89QuOXDpIkKaaHb98uh9XlhB8IMcqzZ1hi2kSadoO7drtOppmeFgYcyOidEuwqQ5%2BksxrOwRb%2F88AfSYEjqUM6U2ldrE8RoUdSf3gQ%3D%3D%3C%2FSignatureValue%3E%3CKeyInfo%3E%3CX509Data%3E%3CX509Certificate%3EMIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S%2Fry7iav%2FIICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei%2BIP3sKmCcMX7Ibsg%2BubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy%2BSVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd%2Fuctpner6oc335rvdJikNmc1cFKCK%2B2irew1bgUJHuN%2BLJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr%2FHCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R%2FX4visjceUlv5jVzCn%2FSIq6Gm9%2FwCqtSxYvifRXxwNpQTOyvHhrY%2FIJLRUp2g9%2FfDELYd65t9Dp%2BN8SznhfB6%2FCl7P7FRo99rIlj%2Fq7JXa8UB%2FvLJPDlr%2BNREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es%2BjuQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ%2FrWQ5J%2F9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A%2FzMOQtoD%3C%2FX509Certificate%3E%3C%2FX509Data%3E%3C%2FKeyInfo%3E%3C%2FSignature%3E%3CSubject%3E%3CNameID+Format%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Anameid-format%3Apersistent%22%3ERrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s%3C%2FNameID%3E%3CSubjectConfirmation+Method%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Acm%3Abearer%22+%2F%3E%3C%2FSubject%3E%3CConditions+NotBefore%3D%222017-04-23T17%3A40%3A36.882Z%22+NotOnOrAfter%3D%222017-04-23T18%3A40%3A36.882Z%22%3E%3CAudienceRestriction%3E%3CAudience%3Espn%3Afe78e0b4-6fe7-47e6-812c-fb75cee266a4%3C%2FAudience%3E%3C%2FAudienceRestriction%3E%3C%2FConditions%3E%3CAttributeStatement%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Ftenantid%22%3E%3CAttributeValue%3Eadd29489-7269-41f4-8841-b63c95564420%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fobjectidentifier%22%3E%3CAttributeValue%3Ed1ad9ce7-b322-4221-ab74-1e1011e1bbcb%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fname%22%3E%3CAttributeValue%3EUser1%40Cyrano.onmicrosoft.com%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fsurname%22%3E%3CAttributeValue%3E1%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fgivenname%22%3E%3CAttributeValue%3EUser%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fdisplayname%22%3E%3CAttributeValue%3EUser1%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fidentityprovider%22%3E%3CAttributeValue%3Ehttps%3A%2F%2Fsts.windows.net%2Fadd29489-7269-41f4-8841-b63c95564420%2F%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fclaims%2Fauthnmethodsreferences%22%3E%3CAttributeValue%3Ehttp%3A%2F%2Fschemas.microsoft.com%2Fws%2F2008%2F06%2Fidentity%2Fauthenticationmethod%2Fpassword%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3C%2FAttributeStatement%3E%3CAuthnStatement+AuthnInstant%3D%222017-04-23T16%3A16%3A17.270Z%22%3E%3CAuthnContext%3E%3CAuthnContextClassRef%3Eurn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Aac%3Aclasses%3APassword%3C%2FAuthnContextClassRef%3E%3C%2FAuthnContext%3E%3C%2FAuthnStatement%3E%3C%2FAssertion%3E%3C%2Ft%3ARequestedSecurityToken%3E%3Ct%3ARequestedAttachedReference%3E%3CSecurityTokenReference+d3p1%3ATokenType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%22+xmlns%3Ad3p1%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-wssecurity-secext-1.1.xsd%22+xmlns%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-secext-1.0.xsd%22%3E%3CKeyIdentifier+ValueType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLID%22%3E_710d4516-27ac-4547-816d-3947aeea6edf%3C%2FKeyIdentifier%3E%3C%2FSecurityTokenReference%3E%3C%2Ft%3ARequestedAttachedReference%3E%3Ct%3ARequestedUnattachedReference%3E%3CSecurityTokenReference+d3p1%3ATokenType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%22+xmlns%3Ad3p1%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-wssecurity-secext-1.1.xsd%22+xmlns%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-secext-1.0.xsd%22%3E%3CKeyIdentifier+ValueType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLID%22%3E_710d4516-27ac-4547-816d-3947aeea6edf%3C%2FKeyIdentifier%3E%3C%2FSecurityTokenReference%3E%3C%2Ft%3ARequestedUnattachedReference%3E%3Ct%3ATokenType%3Ehttp%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%3C%2Ft%3ATokenType%3E%3Ct%3ARequestType%3Ehttp%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F02%2Ftrust%2FIssue%3C%2Ft%3ARequestType%3E%3Ct%3AKeyType%3Ehttp%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2FNoProofKey%3C%2Ft%3AKeyType%3E%3C%2Ft%3ARequestSecurityTokenResponse%3E&wctx=WsFedOwinState%3DZfCHQBMGl9Nia9P6tbsUq5AFCEu9fGolLxTkikMW-zGMhRMsZb6ofrdCD9uni2PoEuW_1zfJPtZawNSjiy4vIg5o2TJeGiwmKjqM0y3bi4w";
            }
        }

        public static WsFederationMessageTestSet WsSignInTestSet
        {
            get
            {
                return new WsFederationMessageTestSet
                {
                    WsFederationMessage = new WsFederationMessage
                    {
                        Wa = WsFederationConstants.WsFederationActions.SignIn,
                        Wresult = Uri.UnescapeDataString(@"%3Ct%3ARequestSecurityTokenResponse+xmlns%3At%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F02%2Ftrust%22%3E%3Ct%3ALifetime%3E%3Cwsu%3ACreated+xmlns%3Awsu%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-utility-1.0.xsd%22%3E2017-04-23T17%3A40%3A36.882Z%3C%2Fwsu%3ACreated%3E%3Cwsu%3AExpires+xmlns%3Awsu%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-utility-1.0.xsd%22%3E2017-04-23T18%3A40%3A36.882Z%3C%2Fwsu%3AExpires%3E%3C%2Ft%3ALifetime%3E%3Cwsp%3AAppliesTo+xmlns%3Awsp%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2004%2F09%2Fpolicy%22%3E%3Cwsa%3AEndpointReference+xmlns%3Awsa%3D%22http%3A%2F%2Fwww.w3.org%2F2005%2F08%2Faddressing%22%3E%3Cwsa%3AAddress%3Espn%3Afe78e0b4-6fe7-47e6-812c-fb75cee266a4%3C%2Fwsa%3AAddress%3E%3C%2Fwsa%3AEndpointReference%3E%3C%2Fwsp%3AAppliesTo%3E%3Ct%3ARequestedSecurityToken%3E%3CAssertion+ID%3D%22_710d4516-27ac-4547-816d-3947aeea6edf%22+IssueInstant%3D%222017-04-23T17%3A45%3A36.882Z%22+Version%3D%222.0%22+xmlns%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Aassertion%22%3E%3CIssuer%3Ehttps%3A%2F%2Fsts.windows.net%2Fadd29489-7269-41f4-8841-b63c95564420%2F%3C%2FIssuer%3E%3CSignature+xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23%22%3E%3CSignedInfo%3E%3CCanonicalizationMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F10%2Fxml-exc-c14n%23%22+%2F%3E%3CSignatureMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256%22+%2F%3E%3CReference+URI%3D%22%23_710d4516-27ac-4547-816d-3947aeea6edf%22%3E%3CTransforms%3E%3CTransform+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23enveloped-signature%22+%2F%3E%3CTransform+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F10%2Fxml-exc-c14n%23%22+%2F%3E%3C%2FTransforms%3E%3CDigestMethod+Algorithm%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmlenc%23sha256%22+%2F%3E%3CDigestValue%3Ekv1eRd%2BMFFaevhwOeeJa5BLkLRV3tFB5QKVD8JBOgMg%3D%3C%2FDigestValue%3E%3C%2FReference%3E%3C%2FSignedInfo%3E%3CSignatureValue%3EABAzMsMPGlKCA0HcmAAiCFwMZr0gtKMUQpRUTCX8YaLAIxOgIW3ZBMTwPHKa2K2lp1Tk97oQBE3S%2Bfg7TKriP1bZB8bdPpfu4GxeeYQteWT7dD%2FJPy1SYCMiRMSsNO4T3O6Keaci1pzwIxzrH8S5s7gzBFPgljf5mHBtZrCTQIK7Ng%2Fnk%2BSpea3RXew05yAQX%2B14Eq6IGPIBsFJidjLqyoslK4OZMNtHLF443AfLs4Ltwfaf89QuOXDpIkKaaHb98uh9XlhB8IMcqzZ1hi2kSadoO7drtOppmeFgYcyOidEuwqQ5%2BksxrOwRb%2F88AfSYEjqUM6U2ldrE8RoUdSf3gQ%3D%3D%3C%2FSignatureValue%3E%3CKeyInfo%3E%3CX509Data%3E%3CX509Certificate%3EMIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S%2Fry7iav%2FIICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei%2BIP3sKmCcMX7Ibsg%2BubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy%2BSVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd%2Fuctpner6oc335rvdJikNmc1cFKCK%2B2irew1bgUJHuN%2BLJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr%2FHCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R%2FX4visjceUlv5jVzCn%2FSIq6Gm9%2FwCqtSxYvifRXxwNpQTOyvHhrY%2FIJLRUp2g9%2FfDELYd65t9Dp%2BN8SznhfB6%2FCl7P7FRo99rIlj%2Fq7JXa8UB%2FvLJPDlr%2BNREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es%2BjuQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ%2FrWQ5J%2F9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A%2FzMOQtoD%3C%2FX509Certificate%3E%3C%2FX509Data%3E%3C%2FKeyInfo%3E%3C%2FSignature%3E%3CSubject%3E%3CNameID+Format%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Anameid-format%3Apersistent%22%3ERrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s%3C%2FNameID%3E%3CSubjectConfirmation+Method%3D%22urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Acm%3Abearer%22+%2F%3E%3C%2FSubject%3E%3CConditions+NotBefore%3D%222017-04-23T17%3A40%3A36.882Z%22+NotOnOrAfter%3D%222017-04-23T18%3A40%3A36.882Z%22%3E%3CAudienceRestriction%3E%3CAudience%3Espn%3Afe78e0b4-6fe7-47e6-812c-fb75cee266a4%3C%2FAudience%3E%3C%2FAudienceRestriction%3E%3C%2FConditions%3E%3CAttributeStatement%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Ftenantid%22%3E%3CAttributeValue%3Eadd29489-7269-41f4-8841-b63c95564420%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fobjectidentifier%22%3E%3CAttributeValue%3Ed1ad9ce7-b322-4221-ab74-1e1011e1bbcb%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fname%22%3E%3CAttributeValue%3EUser1%40Cyrano.onmicrosoft.com%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fsurname%22%3E%3CAttributeValue%3E1%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2Fclaims%2Fgivenname%22%3E%3CAttributeValue%3EUser%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fdisplayname%22%3E%3CAttributeValue%3EUser1%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fidentity%2Fclaims%2Fidentityprovider%22%3E%3CAttributeValue%3Ehttps%3A%2F%2Fsts.windows.net%2Fadd29489-7269-41f4-8841-b63c95564420%2F%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3CAttribute+Name%3D%22http%3A%2F%2Fschemas.microsoft.com%2Fclaims%2Fauthnmethodsreferences%22%3E%3CAttributeValue%3Ehttp%3A%2F%2Fschemas.microsoft.com%2Fws%2F2008%2F06%2Fidentity%2Fauthenticationmethod%2Fpassword%3C%2FAttributeValue%3E%3C%2FAttribute%3E%3C%2FAttributeStatement%3E%3CAuthnStatement+AuthnInstant%3D%222017-04-23T16%3A16%3A17.270Z%22%3E%3CAuthnContext%3E%3CAuthnContextClassRef%3Eurn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Aac%3Aclasses%3APassword%3C%2FAuthnContextClassRef%3E%3C%2FAuthnContext%3E%3C%2FAuthnStatement%3E%3C%2FAssertion%3E%3C%2Ft%3ARequestedSecurityToken%3E%3Ct%3ARequestedAttachedReference%3E%3CSecurityTokenReference+d3p1%3ATokenType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%22+xmlns%3Ad3p1%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-wssecurity-secext-1.1.xsd%22+xmlns%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-secext-1.0.xsd%22%3E%3CKeyIdentifier+ValueType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLID%22%3E_710d4516-27ac-4547-816d-3947aeea6edf%3C%2FKeyIdentifier%3E%3C%2FSecurityTokenReference%3E%3C%2Ft%3ARequestedAttachedReference%3E%3Ct%3ARequestedUnattachedReference%3E%3CSecurityTokenReference+d3p1%3ATokenType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%22+xmlns%3Ad3p1%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-wssecurity-secext-1.1.xsd%22+xmlns%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2F2004%2F01%2Foasis-200401-wss-wssecurity-secext-1.0.xsd%22%3E%3CKeyIdentifier+ValueType%3D%22http%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLID%22%3E_710d4516-27ac-4547-816d-3947aeea6edf%3C%2FKeyIdentifier%3E%3C%2FSecurityTokenReference%3E%3C%2Ft%3ARequestedUnattachedReference%3E%3Ct%3ATokenType%3Ehttp%3A%2F%2Fdocs.oasis-open.org%2Fwss%2Foasis-wss-saml-token-profile-1.1%23SAMLV2.0%3C%2Ft%3ATokenType%3E%3Ct%3ARequestType%3Ehttp%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F02%2Ftrust%2FIssue%3C%2Ft%3ARequestType%3E%3Ct%3AKeyType%3Ehttp%3A%2F%2Fschemas.xmlsoap.org%2Fws%2F2005%2F05%2Fidentity%2FNoProofKey%3C%2Ft%3AKeyType%3E%3C%2Ft%3ARequestSecurityTokenResponse%3E".Replace('+', ' ')),
                        Wctx = Uri.UnescapeDataString(@"WsFedOwinState%3DZfCHQBMGl9Nia9P6tbsUq5AFCEu9fGolLxTkikMW-zGMhRMsZb6ofrdCD9uni2PoEuW_1zfJPtZawNSjiy4vIg5o2TJeGiwmKjqM0y3bi4w".Replace('+', ' '))
                    },
                    Xml = WaSignIn_Valid
                };
            }
        }

        #endregion

        #region Token

        public static string Token_Saml2_Valid
        {
            get
            {
                return @"<Assertion ID=""_edc15efd-1117-4bf9-89da-28b1663fb890"" IssueInstant=""2017-04-23T16:16:17.348Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_edc15efd-1117-4bf9-89da-28b1663fb890""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>DO8QQoO629ApWPV3LiY2epQSv+I82iChybeRrXbhgtw=</DigestValue></Reference></SignedInfo><SignatureValue>O8JNyVKm9I7kMqlsaBgLCNwHA0qdXv34YHBVfg217lgeKkMC5taLU/EH7UeeMtapU6zMafcYoCH+Bp9zoqDpflgs78Hkjgn/dEUtjPFn7211VXClcTNqk+yhqXWtu6SKrabeIhKCKtoMA9lUAB4D6ABesb6MpwbM/ULq7T16tycZ3X//iXHeOiMwNiUAePYF22fmgrqRSDRHyLPtiLskP4UMksWJBrXUV96e9EU9aEciCvYpzMDv/VFUOCLiEkBqCdAtPVwVun+5eRk9zEh6qscWi0kAgFl3W3JhugcTTuGQYHXYVIHxbd5O33MwFIMUOmGrI1EXuk+cHIq2KUtSLg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotBefore=""2017-04-23T16:11:17.348Z"" NotOnOrAfter=""2017-04-23T17:11:17.348Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/claims/authnmethodsreferences""><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-04-23T16:16:17.270Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>";
            }
        }

        #endregion

    }
}
