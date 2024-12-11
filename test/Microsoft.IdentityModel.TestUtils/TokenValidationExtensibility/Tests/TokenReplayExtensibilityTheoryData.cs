// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class TokenReplayExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal TokenReplayExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            DateTime expirationTime,
            TokenReplayValidationDelegate tokenReplayValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                IssuedAt = expirationTime.AddMinutes(-10),
                NotBefore = expirationTime.AddMinutes(-5),
                Expires = expirationTime,
            };

            ValidationParameters.TokenReplayValidator = tokenReplayValidationDelegate;
        }
    }
}
#nullable restore
