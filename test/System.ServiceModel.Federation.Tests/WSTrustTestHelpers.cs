// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace System.ServiceModel.Federation.Tests
{
    static class WSTrustTestHelpers
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
            Binding issuerBinding,
            string issuerAddress = "http://localhost",
            string tokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
            string targetAddress = "http://localhost",
            SecurityKeyType keyType = SecurityKeyType.BearerKey,
            SecurityAlgorithmSuite securityAlgorithmSuite = null,
            MessageSecurityVersion defauiltMessageSecurityVersion = null,
            SecurityBindingElement securityBindingElement = null)
        {
            var requirements = new SecurityTokenRequirement
            {
                TokenType = tokenType
            };

            var issuedTokenParameters = new IssuedSecurityTokenParameters
            {
                IssuerAddress = new EndpointAddress(issuerAddress),
                KeyType = keyType,
                IssuerBinding = issuerBinding,
                DefaultMessageSecurityVersion = defauiltMessageSecurityVersion
            };
            requirements.Properties.Add(IssuerBindingUri, issuerBinding);
            requirements.Properties.Add(TargetAddressUri, new EndpointAddress(targetAddress));
            requirements.Properties.Add(IssuedTokenParametersUri, issuedTokenParameters);
            requirements.Properties.Add(SecurityAlgorithmSuiteUri, securityAlgorithmSuite ?? DefaultSecurityAlgorithmSuite);
            if (securityBindingElement != null)
            {
                requirements.Properties.Add(SecurityBindingElementUri, securityBindingElement);
            }

            return requirements;
        }
    }
}
