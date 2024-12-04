// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens.Extensibility.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(
            nameof(GenerateAlgorithmExtensibilityTestCases),
            parameters: ["JWT", 1],
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
                "JsonWebTokenHandler.ValidateSignature.cs");
        }
    }
}
#nullable restore
