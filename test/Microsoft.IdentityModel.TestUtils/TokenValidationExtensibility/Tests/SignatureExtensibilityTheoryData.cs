// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class SignatureExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal SignatureExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            SignatureValidationDelegate signatureValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
            };

            ValidationParameters.SignatureValidator = signatureValidationDelegate;
        }
    }
}
#nullable restore
