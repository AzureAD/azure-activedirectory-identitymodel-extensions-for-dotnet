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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public static class WsTrustReferenceXml
    {
        public static string WTrustResponseSaml2
        {
            get => @"<t:RequestSecurityTokenResponse xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust"">
                         <t:Lifetime><wsu:Created xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T16:11:17.348Z</wsu:Created>
                            <wsu:Expires xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"">2017-04-23T17:11:17.348Z</wsu:Expires>
                         </t:Lifetime>
                         <wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy"">
                                <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                                    <wsa:Address>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</wsa:Address>
                                </wsa:EndpointReference>
                         </wsp:AppliesTo>
                        <t:RequestedSecurityToken>
                            <Assertion ID=""_edc15efd-1117-4bf9-89da-28b1663fb890"" IssueInstant=""2017-04-23T16:16:17.348Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""/><Reference URI=""#_edc15efd-1117-4bf9-89da-28b1663fb890""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""/><DigestValue>DO8QQoO629ApWPV3LiY2epQSv+I82iChybeRrXbhgtw=</DigestValue></Reference></SignedInfo><SignatureValue>O8JNyVKm9I7kMqlsaBgLCNwHA0qdXv34YHBVfg217lgeKkMC5taLU/EH7UeeMtapU6zMafcYoCH+Bp9zoqDpflgs78Hkjgn/dEUtjPFn7211VXClcTNqk+yhqXWtu6SKrabeIhKCKtoMA9lUAB4D6ABesb6MpwbM/ULq7T16tycZ3X//iXHeOiMwNiUAePYF22fmgrqRSDRHyLPtiLskP4UMksWJBrXUV96e9EU9aEciCvYpzMDv/VFUOCLiEkBqCdAtPVwVun+5eRk9zEh6qscWi0kAgFl3W3JhugcTTuGQYHXYVIHxbd5O33MwFIMUOmGrI1EXuk+cHIq2KUtSLg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">RrX3SPSxDw6z4KHaKB2V_mnv0G-LbRZdYvo1RQa1L7s</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""/></Subject><Conditions NotBefore=""2017-04-23T16:11:17.348Z"" NotOnOrAfter=""2017-04-23T17:11:17.348Z""><AudienceRestriction><Audience>spn:fe78e0b4-6fe7-47e6-812c-fb75cee266a4</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=""http://schemas.microsoft.com/identity/claims/tenantid""><AttributeValue>add29489-7269-41f4-8841-b63c95564420</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/objectidentifier""><AttributeValue>d1ad9ce7-b322-4221-ab74-1e1011e1bbcb</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""><AttributeValue>User1@Cyrano.onmicrosoft.com</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname""><AttributeValue>1</AttributeValue></Attribute><Attribute Name=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname""><AttributeValue>User</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/displayname""><AttributeValue>User1</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/identity/claims/identityprovider""><AttributeValue>https://sts.windows.net/add29489-7269-41f4-8841-b63c95564420/</AttributeValue></Attribute><Attribute Name=""http://schemas.microsoft.com/claims/authnmethodsreferences""><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=""2017-04-23T16:16:17.270Z""><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>
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

        public static string WsTrustResponseEncryptedToken
        {
            get => @"<wst:RequestSecurityTokenResponse xmlns:S=""http://www.w3.org/2003/05/soap-envelope"" xmlns:wst=""http://schemas.xmlsoap.org/ws/2005/02/trust"" xmlns:wsse=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"" xmlns:wsu=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" xmlns:saml=""urn:oasis:names:tc:SAML:1.0:assertion"" xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy"" xmlns:psf=""http://schemas.microsoft.com/Passport/SoapServices/SOAPFault"">
                <wst:TokenType>urn:oasis:names:tc:SAML:1.0</wst:TokenType>
                <wsp:AppliesTo xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                    <wsa:EndpointReference>
                        <wsa:Address>http://exchangecalendarsharing.com</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:Lifetime>
                    <wsu:Created>2010-09-14T23:29:10Z</wsu:Created>
                    <wsu:Expires>2010-09-29T23:29:10Z</wsu:Expires>
                </wst:Lifetime>
                <wst:RequestedSecurityToken>
                    <EncryptedData xmlns=""http://www.w3.org/2001/04/xmlenc#"" Id=""Assertion0"" Type=""http://www.w3.org/2001/04/xmlenc#Element"">
                        <EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#tripledes-cbc""></EncryptionMethod>
                        <ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
                            <EncryptedKey>
                                <EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p""></EncryptionMethod>
                                <ds:KeyInfo Id=""keyinfo"">
                                    <wsse:SecurityTokenReference>
                                        <wsse:KeyIdentifier EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"" ValueType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"">AqfRuZuff12jC4m1vowT/nRnIPc=</wsse:KeyIdentifier>
                                    </wsse:SecurityTokenReference>
                                </ds:KeyInfo>
                                <CipherData>
                                    <CipherValue>OwJ3Wc1bntalVQ4/aJAj/8v5uA9ei6efPaD+fnkJWm800cAE6e0Yv8WAFXWSoDZnE9HTgE7MrTf77WRK1WhsZRkrrIplOzqA9Dthpn1TgshxzYaIgiw9kxY7YUoG7oigUtabMMQ7rEgLRWZjousUHftVXZ/kBIY+SoWXTLTP1YQZr/nBB2UtpWfe3yJ/TppmoTAIp3FkP2/imZA1TyH6KYbNQvdxpjgocYIC5q48R5HFG9su4ZTgRRrRCXLuxqTsyWLB0OD2kBX3hPz45906TLMwkT4wa8oE5eib3mnLOl46U81NvCQmQtoBnzCMxsd4BGLF6Sc4IwxHsVPyjvgeFA==</CipherValue>
                                </CipherData>
                            </EncryptedKey>
                        </ds:KeyInfo>
                        <CipherData>
                            <CipherValue>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</CipherValue>
                        </CipherData>
                    </EncryptedData>
                </wst:RequestedSecurityToken>
                <wst:RequestedAttachedReference>
                    <wsse:SecurityTokenReference>
                        <wsse:KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID"">uuid-2a30da25-d050-4877-9c43-33da0d7e7846</wsse:KeyIdentifier>
                    </wsse:SecurityTokenReference>
                </wst:RequestedAttachedReference>
                <wst:RequestedUnattachedReference>
                    <wsse:SecurityTokenReference>
                        <wsse:KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID"">uuid-2a30da25-d050-4877-9c43-33da0d7e7846</wsse:KeyIdentifier>
                    </wsse:SecurityTokenReference>
                </wst:RequestedUnattachedReference>
                <wst:RequestedProofToken>
                    <wst:BinarySecret>5p76ToaxZXMFm4W6fmCcFXfDPd9WgJIM</wst:BinarySecret>
                </wst:RequestedProofToken>
            </wst:RequestSecurityTokenResponse>";
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
