// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class IssuerExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal IssuerExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            string issuer,
            IssuerValidationDelegateAsync issuerValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = issuer,
            };

            ValidationParameters.IssuerValidatorAsync = issuerValidationDelegate;
        }
    }
}
