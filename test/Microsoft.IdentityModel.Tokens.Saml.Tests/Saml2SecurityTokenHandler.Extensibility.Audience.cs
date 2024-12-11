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
            nameof(GenerateAudienceExtensibilityTestCases),
            parameters: ["SAML2", 2],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_AudienceValidator_Extensibility(
            AudienceExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_AudienceValidator_Extensibility));
        }

        public static TheoryData<AudienceExtensibilityTheoryData> GenerateAudienceExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateAudienceExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "Saml2SecurityTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
