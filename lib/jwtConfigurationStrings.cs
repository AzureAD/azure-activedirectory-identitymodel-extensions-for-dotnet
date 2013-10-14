// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// contains the element and attribute names used in config when parsing the JwtSecurityTokenHandler from XML.
    /// </summary>
    internal static class JwtConfigurationStrings
    {
        public static class Elements
        {
            public const string DefaultTokenLifetimeInMinutes   = "defaultTokenLifetimeInMinutes";
            public const string JwtSecurityTokenRequirement     = "jwtSecurityTokenRequirement";            
            public const string NameClaimType                   = "nameClaimType";            
            public const string MaxTokenSizeInBytes             = "maximumTokenSizeInBytes";
            public const string MaxClockSkewInMinutes           = "maximumClockSkewInMinutes";
            public const string RoleClaimType                   = "roleClaimType";
            public const string SecurityKey                     = "securityKey";
        }

        public static class Attributes
        {
            public const string Name                   = "name";
            public const string RevocationMode         = "issuerCertificateRevocationMode";
            public const string TrustedStoreLocation   = "issuerCertificateTrustedStoreLocation";
            public const string ValidationMode         = "issuerCertificateValidationMode";
            public const string Validator              = "issuerCertificateValidator";
            public const string SymmetricKey           = "symmetricKey";
            public const string Value                  = "value";
        }

        public static class AttributeValues
        {
            public const string X509RevocationModeNoCheck                       = "NoCheck";
            public const string X509RevocationModeOnline                        = "Online";
            public const string X509RevocationModeOffline                       = "Offline";
            public const string X509CertificateValidationModeChainTrust         = "ChainTrust";
            public const string X509CertificateValidationModeCustom             = "Custom";
            public const string X509CertificateValidationModeNone               = "None";
            public const string X509CertificateValidationModePeerTrust          = "PeerTrust";
            public const string X509CertificateValidationModePeerOrChainTrust   = "PeerOrChainTrust";
            public const string X509TrustedStoreLocationCurrentUser             = "CurrentUser";
            public const string X509TrustedStoreLocationLocalMachine            = "LocalMachine";
        }
    }
}