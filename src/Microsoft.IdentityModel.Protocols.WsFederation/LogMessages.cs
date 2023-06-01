// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Microsoft.IdentityModel.Protocols.WsFederation
// Range: 22000 - 22999

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        internal const string IDX22000 = "IDX22000: The parameter '{0}' cannot be a 'null' or an empty object.";

        // wsfederation messages
        internal const string IDX22900 = "IDX22900: Building wsfederation message from query string: '{0}'.";
        internal const string IDX22901 = "IDX22901: Building wsfederation message from uri: '{0}'.";
        internal const string IDX22902 = "IDX22902: Token is not found in Wresult";
        internal const string IDX22903 = "IDX22903: Multiple tokens were found in the RequestSecurityTokenCollection. Only a single token is supported.";
        internal const string IDX22904 = "IDX22904: Wresult does not contain a 'RequestedSecurityToken' element.";

        // xml metadata messages
        internal const string IDX22800 = "IDX22800: Exception thrown while reading WsFederationMetadata. Element '{0}'. Caught exception: '{1}'.";
        internal const string IDX22801 = "IDX22801: entityID attribute is not found in EntityDescriptor element in metadata file.";
        internal const string IDX22802 = "IDX22802: Current name '{0} and namespace '{1}' do not match the expected name '{2}' and namespace '{3}'.";
        internal const string IDX22803 = "IDX22803: Token reference address is missing in PassiveRequestorEndpoint in metadata file.";
        internal const string IDX22804 = "IDX22804: Security token type role descriptor is expected.";
        internal const string IDX22806 = "IDX22806: Key descriptor for signing is missing in security token service type RoleDescriptor.";
        internal const string IDX22807 = "IDX22807: Token endpoint is missing in security token service type RoleDescriptor.";
        internal const string IDX22808 = "IDX22808: 'Use' attribute is missing in KeyDescriptor.";
        internal const string IDX22810 = "IDX22810: 'Issuer' value is missing in wsfederationconfiguration.";
        internal const string IDX22811 = "IDX22811: 'TokenEndpoint' value is missing in wsfederationconfiguration.";
        internal const string IDX22812 = "IDX22812: Element: '{0}' was an empty element. 'TokenEndpoint' value is missing in wsfederationconfiguration.";
        internal const string IDX22813 = "IDX22813: 'ActiveTokenEndpoint' is missing in 'SecurityTokenServiceTypeRoleDescriptor'.";
        internal const string IDX22814 = "IDX22814: Token reference address is missing in SecurityTokenServiceEndpoint in metadata.";

#pragma warning restore 1591
    }
}
