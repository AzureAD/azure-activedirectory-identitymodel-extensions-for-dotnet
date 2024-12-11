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
            nameof(GenerateSignatureExtensibilityTestCases),
            parameters: ["JWT", 3],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_SignatureValidator_Extensibility(
            SignatureExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_SignatureValidator_Extensibility));
        }

        public static TheoryData<SignatureExtensibilityTheoryData> GenerateSignatureExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateSignatureExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "JsonWebTokenHandler.ValidateSignature.cs");
        }
    }
}
#nullable restore
