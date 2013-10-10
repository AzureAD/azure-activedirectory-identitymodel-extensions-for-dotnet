//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

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