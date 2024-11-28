// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml.Extensibility.Tests
{
    public partial class SamlSecurityTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(
            nameof(GenerateIssuerExtensibilityTestCases),
            parameters: ["SAML", 1],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerValidator_Extensibility(
            IssuerExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_IssuerValidator_Extensibility));
        }

        public static TheoryData<IssuerExtensibilityTheoryData> GenerateIssuerExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateIssuerExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "SamlSecurityTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
