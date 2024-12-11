// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class LifetimeExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal LifetimeExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            DateTime utcNow,
            LifetimeValidationDelegate lifetimeValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                IssuedAt = utcNow.AddHours(-1),
                NotBefore = utcNow,
                Expires = utcNow.AddHours(1),
            };

            ValidationParameters.LifetimeValidator = lifetimeValidationDelegate;
        }
    }
}
#nullable restore
