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
            nameof(GenerateLifetimeExtensibilityTestCases),
            parameters: ["SAML", 2],
            DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_LifetimeValidator_Extensibility(
            LifetimeExtensibilityTheoryData theoryData)
        {
            await ExtensibilityTesting.ValidateTokenAsync_Extensibility(
                theoryData,
                this,
                nameof(ValidateTokenAsync_LifetimeValidator_Extensibility));
        }

        public static TheoryData<LifetimeExtensibilityTheoryData> GenerateLifetimeExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames)
        {
            return ExtensibilityTesting.GenerateLifetimeExtensibilityTestCases(
                tokenHandlerType,
                extraStackFrames,
                "SamlSecurityTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
