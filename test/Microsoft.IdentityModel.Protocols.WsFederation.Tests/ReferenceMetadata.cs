using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    public class ReferenceMetadata
    {
        public static string Metadata =
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
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe / 56R3DlWYQanX6cygM=</DigestValue>
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
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
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
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:ApplicationServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:TargetScopes>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:TargetScopes>
                    <fed:ApplicationServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:ApplicationServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <SingleLogoutService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                  </IDPSSODescriptor>
                </EntityDescriptor>";

        public static string MetadataNoIssuer =
            @"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" ID=""_6c4f3672-45c2-47a6-9515-afda95224009"">
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
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe / 56R3DlWYQanX6cygM=</DigestValue>
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
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
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
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:ApplicationServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:TargetScopes>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:TargetScopes>
                    <fed:ApplicationServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:ApplicationServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <SingleLogoutService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                    <SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/saml2"" />
                  </IDPSSODescriptor>
                </EntityDescriptor>";

        public static string MetadataNoTokenUri =
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
                        <DigestValue> i6nrvd1p0+HbCCrFBN5z3jrCe / 56R3DlWYQanX6cygM=</DigestValue>
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
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0/Gz5Xx/zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N/w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK/7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2/DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF/joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
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
                        <wsa:Address>
                          
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:SecurityTokenServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <RoleDescriptor xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:fed=""http://docs.oasis-open.org/wsfed/federation/200706"" xsi:type=""fed:ApplicationServiceType"" protocolSupportEnumeration=""http://docs.oasis-open.org/wsfed/federation/200706"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <fed:TargetScopes>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:TargetScopes>
                    <fed:ApplicationServiceEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:ApplicationServiceEndpoint>
                    <fed:PassiveRequestorEndpoint>
                      <wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing"">
                        <wsa:Address>
                          https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/wsfed
                        </wsa:Address>
                      </wsa:EndpointReference>
                    </fed:PassiveRequestorEndpoint>
                  </RoleDescriptor>
                  <IDPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S / ry7iav / IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd / uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDBTCCAe2gAwIBAgIQXxLnqm1cOoVGe62j7W7wZzANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDMyNjAwMDAwMFoXDTE5MDMyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJGarCm4IF0 / Gz5Xx / zyZwD2rdJJZtO2Ukk1Oz+Br1sLVY8I5vj5esB+lotmLEblA9N / w188vmTvykaEzUl49NA4s86x44SW6WtdQbGJ0IjpQJUalUMyy91vIBkK / 7K3nBXeVBsRk7tm528leoQ05/aZ+1ycJBIU+1oGYThv8MOjyHAlXJmCaGXwXTisZ+hHjcwlMk/+ZEutHflKLIpPUNEi7j4Xw+zp9UKo5pzWIr/iJ4HjvCkFofW90AMF2xp8dMhpbVcfJGS/Ii3J66LuNLCH/HtSZ42FO+tnRL/nNzzFWUhGT92Q5VFVngfWJ3PAg1zz8I1wowLD2fiB2udGXcCAwEAAaMhMB8wHQYDVR0OBBYEFFXPbFXjmMR3BluF+2MeSXd1NQ3rMA0GCSqGSIb3DQEBCwUAA4IBAQAsd3wGVilJxDtbY1K2oAsWLdNJgmCaYdrtdlAsjGlarSQSzBH0Ybf78fcPX//DYaLXlvaEGKVKp0jPq+RnJ17oP/RJpJTwVXPGRIlZopLIgnKpWlS/PS0uKAdNvLmz1zbGSILdcF+Qf41OozD4QNsS1c9YbDO4vpC9v8x3PVjfJvJwPonzNoOsLXA+8IONSXwCApsnmrwepKu8sifsFYSwgrwxRPGTEAjkdzRJ0yMqiY/VoJ7lqJ/FBJqqAjGPGq/yI9rVoG+mbO1amrIDWHHTKgfbKk0bXGtVUbsayyHR5jSgadmkLBh5AaN/HcgDK/jINrnpiQ+/2ewH/8qLaQ3B
                          </X509Certificate>
                        </X509Data>
                      </KeyInfo>
                    </KeyDescriptor>
                    <KeyDescriptor use=""signing"">
                      <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
                        <X509Data>
                          <X509Certificate>
                            MIIDKDCCAhCgAwIBAgIQBHJvVNxP1oZO4HYKh+rypDANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTYxMTE2MDgwMDAwWhcNMTgxMTE2MDgwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn5BCs24Hh6L0BNitPrV5s+2 / DBhaeytOmnghJKnqeJlhv3ZczShRM2Cp38LW8Y3wn7L3AJtolaSkF / joKN1l6GupzM+HOEdq7xZxFehxIHW7+25mG/WigBnhsBzLv1SR4uIbrQeS5M0kkLwJ9pOnVH3uzMGG6TRXPnK3ivlKl97AiUEKdlRjCQNLXvYf1ZqlC77c/ZCOHSX4kvIKR2uG+LNlSTRq2rn8AgMpFT4DSlEZz4RmFQvQupQzPpzozaz/gadBpJy/jgDmJlQMPXkHp7wClvbIBGiGRaY6eZFxNV96zwSR/GPNkTObdw2S8/SiAgvIhIcqWTPLY6aVTqJfAgMBAAGjWDBWMFQGA1UdAQRNMEuAEDUj0BrjP0RTbmoRPTRMY3WhJTAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXOCEARyb1TcT9aGTuB2Cofq8qQwDQYJKoZIhvcNAQELBQADggEBAGnLhDHVz2gLDiu9L34V3ro/6xZDiSWhGyHcGqky7UlzQH3pT5so8iF5P0WzYqVtogPsyC2LPJYSTt2vmQugD4xlu/wbvMFLcV0hmNoTKCF1QTVtEQiAiy0Aq+eoF7Al5fV1S3Sune0uQHimuUFHCmUuF190MLcHcdWnPAmzIc8fv7quRUUsExXmxSX2ktUYQXzqFyIOSnDCuWFm6tpfK5JXS8fW5bpqTlrysXXz/OW/8NFGq/alfjrya4ojrOYLpunGriEtNPwK7hxj1AlCYEWaRHRXaUIW1ByoSff/6Y6+ZhXPUe0cDlNRt/qIz5aflwO7+W8baTS4O8m/icu7ItE=
                          </X509Certificate>
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
