//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Claims;

using ReservedClaims = System.IdentityModel.Tokens.JwtConstants.ReservedClaims;

namespace System.IdentityModel.Tokens
{
    internal static class ClaimTypeMapping
    {
        static ClaimTypeMapping()
        {
            _longToShortClaimTypeMapping = new Dictionary<string, string>();
            foreach ( KeyValuePair< string, string > kv in _shortToLongClaimTypeMapping )
            {
                if ( !_longToShortClaimTypeMapping.ContainsKey( kv.Value ) )
                {
                    _longToShortClaimTypeMapping.Add( kv.Value, kv.Key );
                }
            }
        }

        // this is the short to long mapping.
        // key      is the long  claim type
        // value    is the short claim type
        private static Dictionary<string, string> _shortToLongClaimTypeMapping  
            = new Dictionary<string, string>()
              {
                    // ACS mappings

                    { ReservedClaims.Actor, ClaimTypes.Actor },
                    { ReservedClaims.Birthdate, ClaimTypes.DateOfBirth },
                    { ReservedClaims.Email, ClaimTypes.Email },
                    { ReservedClaims.FamilyName, ClaimTypes.Surname },
                    { ReservedClaims.Gender, ClaimTypes.Gender },
                    { ReservedClaims.GivenName, ClaimTypes.GivenName },
                    { ReservedClaims.NameId, ClaimTypes.NameIdentifier },
                    { ReservedClaims.Subject, ClaimTypes.NameIdentifier },
                    { ReservedClaims.Website, ClaimTypes.Webpage },
                    { ReservedClaims.UniqueName, ClaimTypes.Name },
                    { "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier" },
                    { "scp", "http://schemas.microsoft.com/identity/claims/scope" },
                    { "tid", "http://schemas.microsoft.com/identity/claims/tenantid" },
           
                    // ADFS new mappings
                    { "acr", "http://schemas.microsoft.com/claims/authnclassreference" },
                    { "adfs1email", "http://schemas.xmlsoap.org/claims/EmailAddress" },
                    { "adfs1upn", "http://schemas.xmlsoap.org/claims/UPN" },                  
                    { "amr", "http://schemas.microsoft.com/claims/authnmethodsreferences" },
                    { "auth_time", ClaimTypes.AuthenticationInstant },
                    { "authmethod", ClaimTypes.AuthenticationMethod },
                    { "certapppolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/applicationpolicy" },
                    { "certauthoritykeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/authoritykeyidentifier" },
                    { "certbasicconstraints", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/basicconstraints" },
                    { "certeku", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/eku" },
                    { "certissuer", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer" },
                    { "certissuername", "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuername" },
                    { "certkeyusage", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/keyusage" },
                    { "certnotafter", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notafter" },
                    { "certnotbefore", "http://schemas.microsoft.com/2012/12/certificatecontext/field/notbefore" },
                    { "certpolicy", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatepolicy" },
                    { "certpublickey", ClaimTypes.Rsa },
                    { "certrawdata", "http://schemas.microsoft.com/2012/12/certificatecontext/field/rawdata" },
                    { "certserialnumber", ClaimTypes.SerialNumber },
                    { "certsignaturealgorithm", "http://schemas.microsoft.com/2012/12/certificatecontext/field/signaturealgorithm" },
                    { "certsubject", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subject" },
                    { "certsubjectaltname", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/san" },
                    { "certsubjectkeyidentifier", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/subjectkeyidentifier" },
                    { "certsubjectname", "http://schemas.microsoft.com/2012/12/certificatecontext/field/subjectname" },
                    { "certtemplateinformation", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplateinformation" },
                    { "certtemplatename", "http://schemas.microsoft.com/2012/12/certificatecontext/extension/certificatetemplatename" },
                    { "certthumbprint", ClaimTypes.Thumbprint },
                    { "certx509version", "http://schemas.microsoft.com/2012/12/certificatecontext/field/x509version" },
        	        { "clientapplication", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application" },
                    { "clientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-ip" },
                    { "clientuseragent", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent" },
                    { "commonname", "http://schemas.xmlsoap.org/claims/CommonName" },
                    { "denyonlyprimarygroupsid", ClaimTypes.DenyOnlyPrimaryGroupSid },
                    { "denyonlyprimarysid", ClaimTypes.DenyOnlyPrimarySid },
                    { "denyonlysid", ClaimTypes.DenyOnlySid },
                    { "devicedispname", "http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname" },
                    { "deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier" },
                    { "deviceismanaged", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ismanaged" },
                    { "deviceostype", "http://schemas.microsoft.com/2012/01/devicecontext/claims/ostype" },
                    { "deviceosver", "http://schemas.microsoft.com/2012/01/devicecontext/claims/osversion" },
                    { "deviceowner", "http://schemas.microsoft.com/2012/01/devicecontext/claims/userowner" },
                    { "deviceregid","http://schemas.microsoft.com/2012/01/devicecontext/claims/registrationid" },
                    { "endpointpath", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path" },
                    { "forwardedclientip", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip" },
        	        { "group", "http://schemas.xmlsoap.org/claims/Group" },
                    { "groupsid", ClaimTypes.GroupSid },
                    { "idp", "http://schemas.microsoft.com/identity/claims/identityprovider" },
                    { "insidecorporatenetwork", "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork" },
                    { "isregistereduser", "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser" },
                    { "ppid", System.IdentityModel.Claims.ClaimTypes.PPID },
                    { "primarygroupsid", ClaimTypes.PrimaryGroupSid },
                    { "primarysid", ClaimTypes.PrimarySid },
                    { "proxy", "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy" },
                    { "pwdchgurl", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl" },
                    { "pwdexpdays", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays" },
                    { "pwdexptime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime" },
                    { "relyingpartytrustid", "http://schemas.microsoft.com/2012/01/requestcontext/claims/relyingpartytrustid" },
                    { "role", ClaimTypes.Role },
                    { "upn", ClaimTypes.Upn },
                    { "winaccountname", ClaimTypes.WindowsAccountName },
              };

        private static IDictionary<string, string> _longToShortClaimTypeMapping = null;

        // InboundClaimTypeMap is used by JwtSecurityTokenHandler to lengthen ACS generated claim types that have long names.
        public static IDictionary<string, string> InboundClaimTypeMap
        {
            get
            {
                return _shortToLongClaimTypeMapping;
            }
        }

        // OutboundClaimTypeMap is used by JwtSecurityTokenHandler to lengthen ACS generated claim types that have long names.
        public static IDictionary<string, string> OutboundClaimTypeMap
        {
            get 
            { 
                return _longToShortClaimTypeMapping; 
            }
        }
    }
}