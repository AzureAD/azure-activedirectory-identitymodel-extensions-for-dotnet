// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class TokenTypeExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal TokenTypeExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            string tokenType,
            TokenTypeValidationDelegate tokenTypeValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                TokenType = tokenType,
            };

            ValidationParameters.TokenTypeValidator = tokenTypeValidationDelegate;
        }
    }
}
#nullable restore
