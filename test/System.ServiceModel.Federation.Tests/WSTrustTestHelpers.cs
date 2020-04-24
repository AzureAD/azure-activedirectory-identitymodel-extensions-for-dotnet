// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Selectors;
using System.Reflection;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;

namespace System.ServiceModel.Federation.Tests
{
    static class WsTrustTestHelpers
    {
        const string TargetAddressUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/TargetAddress";
        const string IssuerBindingUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuerBinding";
        const string IssuedTokenParametersUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters";
        const string SecurityAlgorithmSuiteUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/SecurityAlgorithmSuite";
        const string SecurityBindingElementUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/SecurityBindingElement";

        // SecurityAlgorithmSuite.Default isn't exposed publicly because customers aren't expected to need to specify it explicitly.
        // Getting the default algorithm suite here as a testing convenience.
        private static SecurityAlgorithmSuite DefaultSecurityAlgorithmSuite =>
            typeof(SecurityAlgorithmSuite)
            .GetProperty("Default", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .GetValue(null) as SecurityAlgorithmSuite;

        public static SecurityTokenRequirement CreateSecurityRequirement(
            WsTrustTokenParameters wsTrustTokenParameters,
            SecurityAlgorithmSuite securityAlgorithmSuite = null,
            SecurityBindingElement securityBindingElement = null)
        {
            var securityTokenRequirement = new SecurityTokenRequirement
            {
                TokenType = wsTrustTokenParameters.TokenType
            };

            securityTokenRequirement.Properties.Add(IssuerBindingUri, wsTrustTokenParameters.IssuerBinding);
            securityTokenRequirement.Properties.Add(TargetAddressUri, wsTrustTokenParameters.IssuerAddress);
            securityTokenRequirement.Properties.Add(IssuedTokenParametersUri, wsTrustTokenParameters);
            securityTokenRequirement.Properties.Add(SecurityAlgorithmSuiteUri, securityAlgorithmSuite ?? DefaultSecurityAlgorithmSuite);
            if (securityBindingElement != null)
            {
                securityTokenRequirement.Properties.Add(SecurityBindingElementUri, securityBindingElement);
            }

            return securityTokenRequirement;
        }
    }
}
