// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class AudienceExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal AudienceExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            string audience,
            AudienceValidationDelegate audienceValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                Audience = audience,
            };

            ValidationParameters.AudienceValidator = audienceValidationDelegate;
        }
    }
}
#nullable restore
