// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2.Extensibility.Tests
{
    public partial class Saml2SecurityTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(
            nameof(GenerateIssuerSigningKeyExtensibilityTestCases),
            parameters: ["SAML2", 1],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerSigningKeyValidator_Extensibility(
            IssuerSigningKeyExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_IssuerSigningKeyValidator_Extensibility));
        }

        public static TheoryData<IssuerSigningKeyExtensibilityTheoryData> GenerateIssuerSigningKeyExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateIssuerSigningKeyExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "Saml2SecurityTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
