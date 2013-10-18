//-----------------------------------------------------------------------
// <copyright file="WifExtensionsErrors.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
// <license>
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
// </license>

namespace System.IdentityModel
{
    using System.Diagnostics.CodeAnalysis;

    /// <summary>
    /// Errors return from WIF extensions.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    internal static class WifExtensionsErrors
    {
        // general errors 10000 - 10099
        internal const string WIF10000 = "WIF10000: The parameter '{0}' cannot be a 'null' or an empty string.";
        internal const string WIF10001 = "WIF10001: The property value '{0}' cannot be a 'null' or an empty string.";
        internal const string WIF10002 = "WIF10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.";

        // Configuratrion errors for ValidatingIssuerNameRegistry 10100 - 10199
        internal const string WIF10100 = "WIF10100: Only one IssuerNameValidator element is supported. Found multiple. XmlElement: '{0}'";
        internal const string WIF10101 = "WIF10101: Authority name cannot be null or whitespace. XmlElement: '{0}'.";
        internal const string WIF10102 = "WIF10102: Expected xmlElement to have a local name of: '{0}'. XmlElement: '{1}'.";
        internal const string WIF10103 = "WIF10103: Authority names must be unique, found duplicate: '{0}'.";
        internal const string WIF10104 = "WIF10104: Authority must have two child elements: '{0}' and '{1}'. XmlElement: '{2}'.";
        internal const string WIF10106 = "WIF10106: Expecting ChildNode with local name: '{0}' to be of type: '{1}', it was of type: '{2}'.";
        internal const string WIF10107 = "WIF10107: The only supported element inside '{0}' is '{1}'. Found element '{2}'. XmlElement: '{3}'.";
        internal const string WIF10108 = "WIF10108: The '{0}' element must contain at least one of the following attributes: '{1}'  or '{2}'. XmlElement: '{3}'.";
        internal const string WIF10109 = "WIF10109: The '{0}' attribute cannot be null or whitespace. XmlElement: '{1}'.";
        internal const string WIF10110 = "WIF10110: Duplicate: '{0}' found: '{1}'. XmlElement: '{2}'.";
        internal const string WIF10111 = "WIF10111: Expected attribute: '{0}' was not found on element: '{1}'. XmlElement: '{2}'.";
        internal const string WIF10112 = "WIF10112: The only supported element inside '{0}' is '{1}'. Found element '{2}'. XmlElement: '{3}'.";
        internal const string WIF10113 = "WIF10113: Runtime is unable to reslove the type: '{0}'. XmlElement: '{1}'.";
        internal const string WIF10114 = "WIF10114: At least validIssuer must be specified. XmlElement '{0}'.";
        internal const string WIF10115 = "WIF10115: At least one thumbprint or symmetricKey must be specified. XmlElement '{0}'.";
        internal const string WIF10116 = "WIF10116: IssuingAuthority returned form LoadAuthority cannot be null.";
        internal const string WIF10117 = "WIF10117: IssuingAuthority.Name returned form LoadAuthority cannot be null or whitespace.";
        internal const string WIF10118 = "WIF10118: Could not open the configuration file '{0}'. Unable to write the configuration.";
        internal const string WIF10119 = "WIF10119: Unable to read metadata from: '{0}'.  Received the following exception: '{1}'.";
        internal const string WIF10120 = "WIF10120: Metadata must be signed. Metadata was not signed at location: '{0}'.";

        // Runtime errors for ValidatingIssuerNameRegistry 10200 - 10299
        internal const string WIF10200 = "WIF10200: GetIssuerName with single parameter is not supported. Call: 'GetIssuerName( SecurityToken securityToken, string issuer )'.";
        internal const string WIF10201 = "WIF10201: No valid key mapping found for securityToken: '{0}' and issuer: '{1}'.";
    }
}