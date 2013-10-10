//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel
{
    /// <summary>
    /// Defines the element and names used in config.
    /// </summary>
    internal static class ConfigurationStrings
    {

        public const string NamespacePrefix                       = "fed";
        //
        // Federation metadata spec 1.2, section 3.2.2
        // Federation metadata SHOULD be hosted at the following address:
        // http[s]://server-name/FederationMetadata/spec-version/FederationMetadata.xml
        //
        public const string DefaultFederationMetadataPathExtension = "FederationMetadata/2007-06/FederationMetadata.xml";

        public const string Separator                                       = "/";
        public const string PrefixedSeparator                               = Separator + NamespacePrefix + ":";
        public const string Add                                             = "add";
        public const string Authority                                       = "authority";        
        public const string IssuerNameRegistry                              = "issuerNameRegistry";
        public const string Keys                                            = "keys";
        public const string Name                                            = "name";
        public const string SymmetricKey                                    = "symmetricKey";
        public const string Thumbprint                                      = "thumbprint";
        public const string Type                                            = "type";
        public const string Value                                           = "value";
        public const string ValidIssuers                                    = "validIssuers";
        public const string ValidatingIssuerNameRegistry                    = "System.IdentityModel.Tokens.ValidatingIssuerNameRegistry, System.IdentityModel.Tokens.ValidatingIssuerNameRegistry";
    }
}
