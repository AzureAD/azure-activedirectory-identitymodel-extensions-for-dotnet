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
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
    public static class ReferenceMetadata
    {
        public static List<SecurityKey> MetadataSigningKeys
        {
            get => new List<SecurityKey>
            {
                new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(X509CertificateData1))),
                new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(X509CertificateData2))),
                new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(X509CertificateData3)))
            };
        }

        public static SecurityKey MetadataSigningKey
        {
            get => new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(X509CertificateData1)));
        }

        public static string AADCommonMetadata { get => @"<?xml version=""1.0"" encoding=""utf-8""?><EntityDescriptor ID=""_0ded55d8-a72f-4e13-ab9e-f40be80b1476"" entityID=""https://sts.windows.net/{tenantid}/"" xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#_0ded55d8-a72f-4e13-ab9e-f40be80b1476""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>lnicj3SNizOF6QI1rWw8JrouoiXMslqtFB5ztWW6qvs=</DigestValue></Reference></SignedInfo><SignatureValue>KD9uWOD/9pvF1NlNCpYoXymUPS1l9uIBgBDe0uOQgQv+tUI/1jJX4UpjADDHCOx6HCl5ZgZSXNmOC2lLSJEwmv21BZzI+PAOxF5hdH99cS/lMC/hxgyWdLVeGnr1I4WbPxGqVmjFNuBdBMaourO4z/5f3D2JZQmgnlu8H+4gv2SpjeZz/YhIN6ZrNfmHwsKZashMGtSmE5uHro+uO5yO17Gr9YfUbtokLRIq5Dk9kqnxG8YZF1C1nC9O0PMdlHb4ubwgO20Cvz5sU2iswn9m68btS5TLF5OVhETzyKir1QA+H1tCgGRqIWd4Geyoucdct1r4zAJGCNIekdKnY3NXwg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></Signature><RoleDescriptor xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706""><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:ClaimTypesOffered><auth:ClaimType Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Name</auth:DisplayName><auth:Description>The mutable display name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Subject</auth:DisplayName><auth:Description>An immutable, globally unique, non-reusable identifier of the user that is unique to the application for which a token is issued.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Given Name</auth:DisplayName><auth:Description>First name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Surname</auth:DisplayName><auth:Description>Last name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/displayname"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Display Name</auth:DisplayName><auth:Description>Display name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/nickname"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Nick Name</auth:DisplayName><auth:Description>Nick name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Authentication Instant</auth:DisplayName><auth:Description>The time (UTC) when the user is authenticated to Windows Azure Active Directory.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Authentication Method</auth:DisplayName><auth:Description>The method that Windows Azure Active Directory uses to authenticate users.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/objectidentifier"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>ObjectIdentifier</auth:DisplayName><auth:Description>Primary identifier for the user in the directory. Immutable, globally unique, non-reusable.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/tenantid"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>TenantId</auth:DisplayName><auth:Description>Identifier for the user's tenant.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/identityprovider"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>IdentityProvider</auth:DisplayName><auth:Description>Identity provider for the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Email</auth:DisplayName><auth:Description>Email address of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Groups</auth:DisplayName><auth:Description>Groups of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/accesstoken"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>External Access Token</auth:DisplayName><auth:Description>Access token issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>External Access Token Expiration</auth:DisplayName><auth:Description>UTC expiration time of access token issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/identity/claims/openid2_id"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>External OpenID 2.0 Identifier</auth:DisplayName><auth:Description>OpenID 2.0 identifier issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/claims/groups.link"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>GroupsOverageClaim</auth:DisplayName><auth:Description>Issued when number of user's group claims exceeds return limit.</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/role"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>Role Claim</auth:DisplayName><auth:Description>Roles that the user or Service Principal is attached to</auth:Description></auth:ClaimType><auth:ClaimType Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/wids"" xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706""><auth:DisplayName>RoleTemplate Id Claim</auth:DisplayName><auth:Description>Role template id of the Built-in Directory Roles that the user is a member of</auth:Description></auth:ClaimType></fed:ClaimTypesOffered><fed:SecurityTokenServiceEndpoint><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>https://login.microsoftonline.com/common/wsfed</wsa:Address></wsa:EndpointReference></fed:SecurityTokenServiceEndpoint><fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>https://login.microsoftonline.com/common/wsfed</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor><RoleDescriptor xsi:type=""fed:ApplicationServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706""><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:TargetScopes><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>https://sts.windows.net/%7Btenantid%7D/</wsa:Address></wsa:EndpointReference></fed:TargetScopes><fed:ApplicationServiceEndpoint><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>https://login.microsoftonline.com/common/wsfed</wsa:Address></wsa:EndpointReference></fed:ApplicationServiceEndpoint><fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>https://login.microsoftonline.com/common/wsfed</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor><IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=""signing""><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><X509Data><X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/common/saml2"" /><SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/common/saml2"" /><SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://login.microsoftonline.com/common/saml2"" /></IDPSSODescriptor></EntityDescriptor>"; }

        public static string AADCommonMetadataSignatureValue { get => "KD9uWOD/9pvF1NlNCpYoXymUPS1l9uIBgBDe0uOQgQv+tUI/1jJX4UpjADDHCOx6HCl5ZgZSXNmOC2lLSJEwmv21BZzI+PAOxF5hdH99cS/lMC/hxgyWdLVeGnr1I4WbPxGqVmjFNuBdBMaourO4z/5f3D2JZQmgnlu8H+4gv2SpjeZz/YhIN6ZrNfmHwsKZashMGtSmE5uHro+uO5yO17Gr9YfUbtokLRIq5Dk9kqnxG8YZF1C1nC9O0PMdlHb4ubwgO20Cvz5sU2iswn9m68btS5TLF5OVhETzyKir1QA+H1tCgGRqIWd4Geyoucdct1r4zAJGCNIekdKnY3NXwg=="; }

        public static string X509CertificateKeyId1 { get => "6B740DD01652EECE2737E05DAE36C5D18FCB74C3"; }

        public static string X509CertificateKeyId2 { get => "CF4DFDCDDB05BA2CE905F0552B54E7DB940760ED"; }

        public static string X509CertificateKeyId3 { get => "D92E120951ACF1283D2D2E80A8B22AE83A56FA0F"; }

        public static string X509CertificateData1 { get => "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD"; }

        public static string X509CertificateData2 { get => "MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B"; }

        public static string X509CertificateData3 { get => "MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE="; }

        public static string Issuer { get => @"https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"; }

        public static string IssuerForCommon { get => @"https://sts.windows.net/{tenantid}/"; }

        public static string TokenEndpoint { get => @"https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed"; }

        public static string TokenEndpointForCommon { get => @"https://login.microsoftonline.com/common/wsfed"; }

        public static string KeyDescriptorNoKeyUse
        {
            get
            {
                return
                @"<KeyDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"">
                   <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                     <X509Data>
                       <X509Certificate>
                         MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                       </X509Certificate>
                     </X509Data>
                    </KeyInfo>
                  </KeyDescriptor>";
            }
        }

        public static string KeyDescriptorKeyUseNotForSigning
        {
            get
            {
                return
                @"<KeyDescriptor use=""Not for signing"" xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"">
                   <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                     <X509Data>
                       <X509Certificate>
                         MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                       </X509Certificate>
                     </X509Data>
                    </KeyInfo>
                  </KeyDescriptor>";
            }
        }

        public static string AADCommonMetadataFormated
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                      <Reference URI=""#_6c4f3672-45c2-47a6-9515-afda95224009"">
                        <Transforms>
                          <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                          <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                        </Transforms>
                        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe/56R3DlWYQanX6cygM=</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>gdmviHtNhy8FQ6gSbyovhzMBxioMs6hoHYYzoyjS4DxHqhLgaPrRe948NKfXRYe4o1syVp+cZaGTcRzlPmCFOxH1zjY9qPUT2tCsJ1aCUCoiepu0uYGkWKV9CifHt7+aixQEufxM06iwZcMdfXPF3lqqdOoC7pRTcPlBJo6m6odXmjIcHPpsBGtkJuS7W6JULFhzBC9ytS0asrVaEZhVijP95QM0SZRL/pnJp1gOtKYKsQV246lV8tHFfFIddtklVYTvhlagjVUHsUtUhfwrt/5i/Rnr40qMNx/H10ZClTAQXthQH3GnzObAmhfoMNS1hAMpnX4BEhBOAqHHv2jyPA==</SignatureValue>
                    <KeyInfo>
                      <X509Data>
                        <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                      </X509Data>
                    </KeyInfo>
                  </Signature>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:ClaimTypesOffered>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"">
                        <auth:DisplayName>Name</auth:DisplayName>
                        <auth:Description>The mutable display name of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"">
                        <auth:DisplayName>Subject</auth:DisplayName>
                        <auth:Description>
                          An immutable, globally unique, non-reusable identifier of the user that is unique to the application for which a token is issued.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"">
                        <auth:DisplayName>Given Name</auth:DisplayName>
                        <auth:Description>First name of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"">
                        <auth:DisplayName>Surname</auth:DisplayName>
                        <auth:Description>Last name of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/displayname"">
                        <auth:DisplayName>Display Name</auth:DisplayName>
                        <auth:Description>Display name of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/nickname"">
                        <auth:DisplayName>Nick Name</auth:DisplayName>
                        <auth:Description>Nick name of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"">
                        <auth:DisplayName>Authentication Instant</auth:DisplayName>
                        <auth:Description>
                          The time (UTC) when the user is authenticated to Windows Azure Active Directory.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"">
                        <auth:DisplayName>Authentication Method</auth:DisplayName>
                        <auth:Description>
                          The method that Windows Azure Active Directory uses to authenticate users.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/objectidentifier"">
                        <auth:DisplayName>ObjectIdentifier</auth:DisplayName>
                        <auth:Description>
                          Primary identifier for the user in the directory. Immutable, globally unique, non-reusable.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/tenantid"">
                        <auth:DisplayName>TenantId</auth:DisplayName>
                        <auth:Description>Identifier for the user's tenant.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/identityprovider"">
                        <auth:DisplayName>IdentityProvider</auth:DisplayName>
                        <auth:Description>Identity provider for the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"">
                        <auth:DisplayName>Email</auth:DisplayName>
                        <auth:Description>Email address of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"">
                        <auth:DisplayName>Groups</auth:DisplayName>
                        <auth:Description>Groups of the user.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/accesstoken"">
                        <auth:DisplayName>External Access Token</auth:DisplayName>
                        <auth:Description>Access token issued by external identity provider.</auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration"">
                        <auth:DisplayName>External Access Token Expiration</auth:DisplayName>
                        <auth:Description>
                          UTC expiration time of access token issued by external identity provider.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/identity/claims/openid2_id"">
                        <auth:DisplayName>External OpenID 2.0 Identifier</auth:DisplayName>
                        <auth:Description>
                          OpenID 2.0 identifier issued by external identity provider.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/claims/groups.link"">
                        <auth:DisplayName>GroupsOverageClaim</auth:DisplayName>
                        <auth:Description>
                          Issued when number of user's group claims exceeds return limit.
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/role"">
                        <auth:DisplayName>Role Claim</auth:DisplayName>
                        <auth:Description>
                          Roles that the user or Service Principal is attached to
                        </auth:Description>
                      </auth:ClaimType>
                      <auth:ClaimType xmlns:auth=""http://docs.oasis-open.org/wsfed/authorization/200706"" Uri=""http://schemas.microsoft.com/ws/2008/06/identity/claims/wids"">
                        <auth:DisplayName>RoleTemplate Id Claim</auth:DisplayName>
                        <auth:Description>
                          Role template id of the Built-in Directory Roles that the user is a member of
                        </auth:Description>
                      </auth:ClaimType>
                    </fed:ClaimTypesOffered>
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed</wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed</wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:ApplicationServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:TargetScopes>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/</wsa:Address>
                      </wsa:EndpointReference>
                    </fed:TargetScopes>
                    <fed:ApplicationServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed</wsa:Address>
                      </wsa:EndpointReference>
                    </fed:ApplicationServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed</wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <SingleLogoutService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                  </IDPSSODescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataMalformedCertificate
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                            <X509Certificate>%%MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>                    
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoAddressInEndpointReference
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>                    
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:_Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:_Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoEndpointReference
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>                    
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:_EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:_EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoEntityDescriptor
        {
            get
            {
                return
                @"<_EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  </_EntityDescriptor>";
            }
        }

        public static string MetadataNoIssuer
        {
            get
            {
                return @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009""></EntityDescriptor>";
            }
        }

        public static string MetadataNoKeyDescriptorForSigningInRoleDescriptor
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <_KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </_KeyDescriptor>                    
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoKeyInfoInKeyDescriptor
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <_KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </_KeyInfo>
                    </KeyDescriptor>                    
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataUnknownElementBeforeSignatureEndElement
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                      <Reference URI=""#_6c4f3672-45c2-47a6-9515-afda95224009"">
                        <Transforms>
                          <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                          <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                        </Transforms>
                        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe/56R3DlWYQanX6cygM=</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>
                      gdmviHtNhy8FQ6gSbyovhzMBxioMs6hoHYYzoyjS4DxHqhLgaPrRe948NKfXRYe4o1syVp+cZaGTcRzlPmCFOxH1zjY9qPUT2tCsJ1aCUCoiepu0uYGkWKV9CifHt7+aixQEufxM06iwZcMdfXPF3lqqdOoC7pRTcPlBJo6m6odXmjIcHPpsBGtkJuS7W6JULFhzBC9ytS0asrVaEZhVijP95QM0SZRL/pnJp1gOtKYKsQV246lV8tHFfFIddtklVYTvhlagjVUHsUtUhfwrt/5i/Rnr40qMNx/H10ZClTAQXthQH3GnzObAmhfoMNS1hAMpnX4BEhBOAqHHv2jyPA==
                    </SignatureValue>
                    <_KeyInfo>
                      <X509Data>
                        <X509Certificate>
                          MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                        </X509Certificate>
                      </X509Data>
                    </_KeyInfo>
                  </Signature>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoRoleDescriptor
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <_RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </_RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoSecurityTokenSeviceEndpointInRoleDescriptor
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">                    
                    <fed:_SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:_SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoSignedInfoInSignature
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <_SignedInfo>
                      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                      <Reference URI=""#_6c4f3672-45c2-47a6-9515-afda95224009"">
                        <Transforms>
                          <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                          <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                        </Transforms>
                        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe/56R3DlWYQanX6cygM=</DigestValue>
                      </Reference>
                    </_SignedInfo>
                    <SignatureValue>
                      gdmviHtNhy8FQ6gSbyovhzMBxioMs6hoHYYzoyjS4DxHqhLgaPrRe948NKfXRYe4o1syVp+cZaGTcRzlPmCFOxH1zjY9qPUT2tCsJ1aCUCoiepu0uYGkWKV9CifHt7+aixQEufxM06iwZcMdfXPF3lqqdOoC7pRTcPlBJo6m6odXmjIcHPpsBGtkJuS7W6JULFhzBC9ytS0asrVaEZhVijP95QM0SZRL/pnJp1gOtKYKsQV246lV8tHFfFIddtklVYTvhlagjVUHsUtUhfwrt/5i/Rnr40qMNx/H10ZClTAQXthQH3GnzObAmhfoMNS1hAMpnX4BEhBOAqHHv2jyPA==
                    </SignatureValue>
                    <KeyInfo>
                      <X509Data>
                        <X509Certificate>
                          MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                        </X509Certificate>
                      </X509Data>
                    </KeyInfo>
                  </Signature>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataNoTokenUri
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">
                  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                      <Reference URI=""#_6c4f3672-45c2-47a6-9515-afda95224009"">
                        <Transforms>
                          <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                          <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                        </Transforms>
                        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe/56R3DlWYQanX6cygM=</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>
                      gdmviHtNhy8FQ6gSbyovhzMBxioMs6hoHYYzoyjS4DxHqhLgaPrRe948NKfXRYe4o1syVp+cZaGTcRzlPmCFOxH1zjY9qPUT2tCsJ1aCUCoiepu0uYGkWKV9CifHt7+aixQEufxM06iwZcMdfXPF3lqqdOoC7pRTcPlBJo6m6odXmjIcHPpsBGtkJuS7W6JULFhzBC9ytS0asrVaEZhVijP95QM0SZRL/pnJp1gOtKYKsQV246lV8tHFfFIddtklVYTvhlagjVUHsUtUhfwrt/5i/Rnr40qMNx/H10ZClTAQXthQH3GnzObAmhfoMNS1hAMpnX4BEhBOAqHHv2jyPA==
                    </SignatureValue>
                    <KeyInfo>
                      <X509Data>
                        <X509Certificate>
                          MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                        </X509Certificate>
                      </X509Data>
                    </KeyInfo>
                  </Signature>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <fed:SecurityTokenServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                  </RoleDescriptor>
                </EntityDescriptor>";
            }
        }

        public static string MetadataWithBlanks
        {
            get
            {
                return
                @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"" entityID=""https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/"">

                  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                    <SignedInfo>
                      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
                      <Reference URI=""#_6c4f3672-45c2-47a6-9515-afda95224009"">
                        <Transforms>
                          <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                          <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
                        </Transforms>
                        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe/56R3DlWYQanX6cygM=</DigestValue>
                      </Reference>
                    </SignedInfo>
                    <SignatureValue>
                      gdmviHtNhy8FQ6gSbyovhzMBxioMs6hoHYYzoyjS4DxHqhLgaPrRe948NKfXRYe4o1syVp+cZaGTcRzlPmCFOxH1zjY9qPUT2tCsJ1aCUCoiepu0uYGkWKV9CifHt7+aixQEufxM06iwZcMdfXPF3lqqdOoC7pRTcPlBJo6m6odXmjIcHPpsBGtkJuS7W6JULFhzBC9ytS0asrVaEZhVijP95QM0SZRL/pnJp1gOtKYKsQV246lV8tHFfFIddtklVYTvhlagjVUHsUtUhfwrt/5i/Rnr40qMNx/H10ZClTAQXthQH3GnzObAmhfoMNS1hAMpnX4BEhBOAqHHv2jyPA==
                    </SignatureValue>
                    <KeyInfo>
                      <X509Data>
                        <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                      </X509Data>
                    </KeyInfo>
                  </Signature>

                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:SecurityTokenServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    
                    <KeyDescriptor use=""signing"">

                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD</X509Certificate>
                        </X509Data>
                      </KeyInfo>

                    </KeyDescriptor>

                    <KeyDescriptor use=""signing"">

                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B</X509Certificate>
                        </X509Data>
                      </KeyInfo>

                    </KeyDescriptor>

                    <KeyDescriptor use=""signing"">

                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=</X509Certificate>
                        </X509Data>
                      </KeyInfo>

                    </KeyDescriptor>

                    <fed:SecurityTokenServiceEndpoint>

                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">

                        <wsa:Address>https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed</wsa:Address>

                      </wsa:EndpointReference>

                    </fed:SecurityTokenServiceEndpoint>

                  </RoleDescriptor>

                </EntityDescriptor>";
            }
        }

        public static WsFederationConfiguration AADCommonFormated
        {
            get
            {
                var configuration = new WsFederationConfiguration()
                {
                    Issuer = "https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/",
                    Signature = new Signature()
                    {
                        KeyInfo = new KeyInfo
                        {
                            CertificateData = X509CertificateData1,
                            Kid = X509CertificateKeyId1
                        },
                        SignatureValue = AADCommonMetadataSignatureValue,
                        SignedInfo = new SignedInfo()
                    },
                    TokenEndpoint = "https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed"
                };

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData1,
                    Kid = X509CertificateKeyId1
                });

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData2,
                    Kid = X509CertificateKeyId2
                });

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData3,
                    Kid = X509CertificateKeyId3
                });

                foreach (var key in MetadataSigningKeys)
                    configuration.SigningKeys.Add(key);

                return configuration;
            }
        }

        public static WsFederationConfiguration AADCommonEndpoint
        {
            get
            {
                // good configuration for common endpoint
                var configuration = new WsFederationConfiguration()
                {
                    Issuer = IssuerForCommon,
                    Signature = new Signature
                    {
                        KeyInfo = new KeyInfo
                        {
                            CertificateData = X509CertificateData1,
                            Kid = X509CertificateKeyId1
                        },
                        SignatureValue = AADCommonMetadataSignatureValue,
                        SignedInfo = new SignedInfo()
                    },
                    TokenEndpoint = TokenEndpointForCommon
                };

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData1,
                    Kid = X509CertificateKeyId1
                });

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData2,
                    Kid = X509CertificateKeyId2
                });

                configuration.KeyInfos.Add(new KeyInfo
                {
                    CertificateData = X509CertificateData3,
                    Kid = X509CertificateKeyId3
                });

                foreach(var key in MetadataSigningKeys)
                    configuration.SigningKeys.Add(key);

                return configuration;
            }
        }
    }

}
