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
            nameof(GenerateTokenReplayExtensibilityTestCases),
            parameters: ["SAML2", 1],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_TokenReplayValidator_Extensibility(
            TokenReplayExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_TokenReplayValidator_Extensibility));
        }

        public static TheoryData<TokenReplayExtensibilityTheoryData> GenerateTokenReplayExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateTokenReplayExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "Saml2SecurityTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
