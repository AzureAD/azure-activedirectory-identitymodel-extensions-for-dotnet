//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel
{
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    /// Defines the element and names used in config.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private fields.")]
    internal static class ConfigurationStrings
    {
        public const string NamespacePrefix                       = "fed";

        // Federation metadata spec 1.2, section 3.2.2
        // Federation metadata SHOULD be hosted at the following address:
        // http[s]://server-name/FederationMetadata/spec-version/FederationMetadata.xml        
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
