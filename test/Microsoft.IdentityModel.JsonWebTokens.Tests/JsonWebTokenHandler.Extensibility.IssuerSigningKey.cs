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
            nameof(GenerateIssuerSigningKeyExtensibilityTestCases),
            parameters: ["JWT", 2],
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
                "JsonWebTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
