
# Claims

Type | Accessor | Used for authorization | Privacy | Claims
--   | --       | --                     | --      | --     
string | GetActor | False |  | JwtRegisteredClaimNames.Actort<BR/> ClaimTypes.Actor
string | GetBirthdate | False | EUII | JwtRegisteredClaimNames.Birthdate<BR/> ClaimTypes.DateOfBirth
string | GetEmail | False | EUII | JwtRegisteredClaimNames.Email<BR/> ClaimTypes.Email
string | GetFamilyName | False | EUII | JwtRegisteredClaimNames.FamilyName<BR/> ClaimTypes.Surname
string | GetGender | False | EUII | JwtRegisteredClaimNames.Gender<BR/> ClaimTypes.Gender
string | GetGivenName | False | EUII | JwtRegisteredClaimNames.GivenName<BR/> ClaimTypes.GivenName
string | GetNameId | False |  | JwtRegisteredClaimNames.NameId<BR/> ClaimTypes.NameIdentifier
string | GetSubject | False |  | JwtRegisteredClaimNames.Sub<BR/> ClaimTypes.NameIdentifier
string | GetWebsite | False |  | JwtRegisteredClaimNames.Website<BR/> ClaimTypes.Webpage
string | GetUniqueName | False | EUPI | JwtRegisteredClaimNames.UniqueName<BR/> ClaimTypes.Name
string | GetObjectId | True | EUPI | "oid"<BR/> "http://schemas.microsoft.com/identity/claims/objectidentifier"
IEnumerable<string> | GetScopes | True |  | "scp"<BR/> "http://schemas.microsoft.com/identity/claims/scope"
string | GetTenantId | True | OII | "tid"<BR/> "http://schemas.microsoft.com/identity/claims/tenantid"
string | GetAcr | False |  | "acr"<BR/> "http://schemas.microsoft.com/claims/authnclassreference"
string | GetAdfs1Email | False | EUPI | "adfs1email"<BR/> "http://schemas.xmlsoap.org/claims/EmailAddress"
string | GetAdfs1Upn | False | EUPI | "adfs1upn"<BR/> "http://schemas.xmlsoap.org/claims/UPN"
string | GetAmr | False |  | "amr"<BR/> "http://schemas.microsoft.com/claims/authnmethodsreferences"
string | GetAuthenticationMethod | False |  | "authmethod"<BR/> ClaimTypes.AuthenticationMethod
string | GetCertAppPolicy | False |  | "certapppolicy"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy"
string | GetCertAuthorityKeyIdentifier | False |  | "certauthoritykeyidentifier"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier"
string | GetCertBasicConstraints | False |  | "certbasicconstraints"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints"
string | GetCertEku | False |  | "certeku"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku"
string | GetCertIssuer | False |  | "certissuer"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer"
string | GetCertIssuerName | False |  | "certissuername"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername"
string | GetCertKeyUsage | False |  | "certkeyusage"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage"
string | GetCertNotAfter | False |  | "certnotafter"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter"
string | GetCertNotBefore | False |  | "certnotbefore"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore"
string | GetCertPolicy | False |  | "certpolicy"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy"
string | GetCertPublickey | False |  | "certpublickey"<BR/> ClaimTypes.Rsa
string | GetCertRawData | False |  | "certrawdata"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata"
string | GetCertSerialNumber | False |  | "certserialnumber"<BR/> ClaimTypes.SerialNumber
string | GetCertSignatureAlgorithm | False |  | "certsignaturealgorithm"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm"
string | GetCertSubject | False |  | "certsubject"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/subject"
string | GetCertSubjectAltName | False |  | "certsubjectaltname"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/san"
string | GetCertSubjectKeyIdentifier | False |  | "certsubjectkeyidentifier"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier"
string | GetCertSubjectName | False |  | "certsubjectname"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname"
string | GetCertTemplateInformation | False |  | "certtemplateinformation"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation"
string | GetCertTemplateName | False |  | "certtemplatename"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename"
string | GetCertThumbprint | False |  | "certthumbprint"<BR/> ClaimTypes.Thumbprint
string | GetCertX509Version | False |  | "certx509version"<BR/> "http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version"
string | GetClientApplication | True |  | "clientapplication"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application"
string | GetClientIp | False | EUPI | "clientip"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip"
string | GetClientUserAgent | False |  | "clientuseragent"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent"
string | GetCommonName | False | EUPI | "commonname"<BR/> "http://schemas.xmlsoap.org/claims/CommonName"
string | GetDenyOnlyPrimaryGroupSid | False |  | "denyonlyprimarygroupsid"<BR/> ClaimTypes.DenyOnlyPrimaryGroupSid
string | GetDenyOnlyPrimarySid | False |  | "denyonlyprimarysid"<BR/> ClaimTypes.DenyOnlyPrimarySid
string | GetDenyOnlySid | False |  | "denyonlysid"<BR/> ClaimTypes.DenyOnlySid
string | GetDevicedIspName | False |  | "devicedispname"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname"
string | GetDeviceId | False |  | "deviceid"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier"
string | GetDeviceIsManaged | False |  | "deviceismanaged"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged"
string | GetDeviceOsType | False |  | "deviceostype"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype"
string | GetDeviceOsVer | False |  | "deviceosver"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion"
string | GetDeviceOwner | False |  | "deviceowner"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner"
string | GetDeviceRegId | False |  | "deviceregid"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid"
string | GetEndpointPath | False |  | "endpointpath"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path"
string | GetForwardedClientIp | False |  | "forwardedclientip"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip"
IEnumerable<string> | GetGroup | False |  | "group"<BR/> "http://schemas.xmlsoap.org/claims/Group"
IEnumerable<string> | GetGroupsId | False |  | "groupsid"<BR/> ClaimTypes.GroupSid
string | GetTokenType | False |  | "idtyp"
string | GetIdp | True |  | "idp"<BR/> "http://schemas.microsoft.com/identity/claims/identityprovider"
string | GetInsideCorporateNetwork | True |  | "insidecorporatenetwork"<BR/> "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork"
string | GetIsRegisteredUser | True |  | "isregistereduser"<BR/> "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser"
string | GetPrivatePersonalIdentifier | False | EUPI | "ppid"<BR/> "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"
string | GetPrimaryGroupSid | True |  | "primarygroupsid"<BR/> ClaimTypes.PrimaryGroupSid
string | GetPrimarySid | True |  | "primarysid"<BR/> ClaimTypes.PrimarySid
string | GetProxy | False |  | "proxy"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"
string | GetPwdChgEndpoint | False |  | "pwdchgurl"<BR/> "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl"
string | GetPwdExpDays | False |  | "pwdexpdays"<BR/> "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays"
string | GetPwdExpTime | False |  | "pwdexptime"<BR/> "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime"
string | GetRelyingPartyTrustId | False |  | "relyingpartytrustid"<BR/> "http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid"
IEnumerable<string> | GetRole | True |  | "role"<BR/> "roles"<BR/> ClaimTypes.Role
string | GetSid | True |  | "sid"
string | GetUpn | False | EUPI | "upn"<BR/> ClaimTypes.Upn
string | GetWindowsAccountName | False | EUPI | "winaccountname"<BR/> ClaimTypes.WindowsAccountName
string | GetVerifiedPrimaryEmail | False | EUPI | "verified_primary_email"
string | GetVerifiedSecondaryEmail | False | EUPI | "verified_secondary_email"
string | GetVNet | False |  | "vnet"
string | GetPreferedDataLocation | False |  | "xms_pdl"
string | GetUserPreferedLanguage | False |  | "xms_tpl"
string | GetZeroTouchDeploymentId | False |  | "ztdid"
