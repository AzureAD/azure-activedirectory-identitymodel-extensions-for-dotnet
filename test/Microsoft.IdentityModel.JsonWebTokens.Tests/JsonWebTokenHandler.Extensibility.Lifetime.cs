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
            nameof(GenerateLifetimeExtensibilityTestCases),
            parameters: ["JWT", 2],
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
                "JsonWebTokenHandler.ValidateToken.Internal.cs");
        }
    }
}
#nullable restore
