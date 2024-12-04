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
            nameof(GenerateAlgorithmExtensibilityTestCases),
            parameters: ["SAML", 1],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_AlgorithmValidator_Extensibility(
            AlgorithmExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_AlgorithmValidator_Extensibility));
        }

        public static TheoryData<AlgorithmExtensibilityTheoryData> GenerateAlgorithmExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateAlgorithmExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "SamlSecurityTokenHandler.ValidateSignature.cs");
        }
    }
}
#nullable restore
