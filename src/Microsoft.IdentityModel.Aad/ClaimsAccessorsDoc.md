
# Claims

Type | Accessor | Used for authorization | Privacy | Claims
--   | --       | --                     | --      | --     
string | GetActor | False |  | actort<BR/> http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor
string | GetBirthdate | False | EUII | birthdate<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth
string | GetEmail | False | EUII | email<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
string | GetFamilyName | False | EUII | family_name<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
string | GetGender | False | EUII | gender<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender
string | GetGivenName | False | EUII | given_name<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
string | GetNameId | False |  | nameid<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier
string | GetSubject | False |  | sub<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier
string | GetWebsite | False |  | website<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage
string | GetUniqueName | False | EUPI | unique_name<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
string | GetObjectId | True | EUPI | oid<BR/> http://schemas.microsoft.com/identity/claims/objectidentifier
IEnumerable<string> | GetScopes | True |  | scp<BR/> http://schemas.microsoft.com/identity/claims/scope
string | GetTenantId | True | OII | tid<BR/> http://schemas.microsoft.com/identity/claims/tenantid
string | GetAcr | False |  | acr<BR/> http://schemas.microsoft.com/claims/authnclassreference
string | GetAdfs1Email | False | EUPI | adfs1email<BR/> http://schemas.xmlsoap.org/claims/EmailAddress
string | GetAdfs1Upn | False | EUPI | adfs1upn<BR/> http://schemas.xmlsoap.org/claims/UPN
string | GetAmr | False |  | amr<BR/> http://schemas.microsoft.com/claims/authnmethodsreferences
string | GetAuthenticationMethod | False |  | authmethod<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod
string | GetCertAppPolicy | False |  | certapppolicy<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy
string | GetCertAuthorityKeyIdentifier | False |  | certauthoritykeyidentifier<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier
string | GetCertBasicConstraints | False |  | certbasicconstraints<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints
string | GetCertEku | False |  | certeku<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku
string | GetCertIssuer | False |  | certissuer<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer
string | GetCertIssuerName | False |  | certissuername<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername
string | GetCertKeyUsage | False |  | certkeyusage<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage
string | GetCertNotAfter | False |  | certnotafter<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter
string | GetCertNotBefore | False |  | certnotbefore<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore
string | GetCertPolicy | False |  | certpolicy<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy
string | GetCertPublickey | False |  | certpublickey<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa
string | GetCertRawData | False |  | certrawdata<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata
string | GetCertSerialNumber | False |  | certserialnumber<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/serialnumber
string | GetCertSignatureAlgorithm | False |  | certsignaturealgorithm<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm
string | GetCertSubject | False |  | certsubject<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/subject
string | GetCertSubjectAltName | False |  | certsubjectaltname<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/san
string | GetCertSubjectKeyIdentifier | False |  | certsubjectkeyidentifier<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier
string | GetCertSubjectName | False |  | certsubjectname<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname
string | GetCertTemplateInformation | False |  | certtemplateinformation<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation
string | GetCertTemplateName | False |  | certtemplatename<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename
string | GetCertThumbprint | False |  | certthumbprint<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/thumbprint
string | GetCertX509Version | False |  | certx509version<BR/> http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version
string | GetClientApplication | True |  | clientapplication<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application
string | GetClientIp | False | EUPI | clientip<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip
string | GetClientUserAgent | False |  | clientuseragent<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent
string | GetCommonName | False | EUPI | commonname<BR/> http://schemas.xmlsoap.org/claims/CommonName
string | GetDenyOnlyPrimaryGroupSid | False |  | denyonlyprimarygroupsid<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid
string | GetDenyOnlyPrimarySid | False |  | denyonlyprimarysid<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid
string | GetDenyOnlySid | False |  | denyonlysid<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid
string | GetDevicedIspName | False |  | devicedispname<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname
string | GetDeviceId | False |  | deviceid<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier
string | GetDeviceIsManaged | False |  | deviceismanaged<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged
string | GetDeviceOsType | False |  | deviceostype<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype
string | GetDeviceOsVer | False |  | deviceosver<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion
string | GetDeviceOwner | False |  | deviceowner<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner
string | GetDeviceRegId | False |  | deviceregid<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid
string | GetEndpointPath | False |  | endpointpath<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path
string | GetForwardedClientIp | False |  | forwardedclientip<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip
IEnumerable<string> | GetGroup | False |  | group<BR/> http://schemas.xmlsoap.org/claims/Group
IEnumerable<string> | GetGroupsId | False |  | groupsid<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid
string | GetTokenType | False |  | idtyp
string | GetIdp | True |  | idp<BR/> http://schemas.microsoft.com/identity/claims/identityprovider
string | GetInsideCorporateNetwork | True |  | insidecorporatenetwork<BR/> http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork
string | GetIsRegisteredUser | True |  | isregistereduser<BR/> http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser
string | GetPrivatePersonalIdentifier | False | EUPI | ppid<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier
string | GetPrimaryGroupSid | True |  | primarygroupsid<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid
string | GetPrimarySid | True |  | primarysid<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid
string | GetProxy | False |  | proxy<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy
string | GetPwdChgEndpoint | False |  | pwdchgurl<BR/> http://schemas.microsoft.com/ws/2012/01/passwordchangeurl
string | GetPwdExpDays | False |  | pwdexpdays<BR/> http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays
string | GetPwdExpTime | False |  | pwdexptime<BR/> http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime
string | GetRelyingPartyTrustId | False |  | relyingpartytrustid<BR/> http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid
IEnumerable<string> | GetRole | True |  | role<BR/> roles<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/role
string | GetSid | True |  | sid
string | GetUpn | False | EUPI | upn<BR/> http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
string | GetWindowsAccountName | False | EUPI | winaccountname<BR/> http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname
string | GetVerifiedPrimaryEmail | False | EUPI | verified_primary_email
string | GetVerifiedSecondaryEmail | False | EUPI | verified_secondary_email
string | GetVNet | False |  | vnet
string | GetPreferedDataLocation | False |  | xms_pdl
string | GetUserPreferedLanguage | False |  | xms_tpl
string | GetZeroTouchDeploymentId | False |  | ztdid

