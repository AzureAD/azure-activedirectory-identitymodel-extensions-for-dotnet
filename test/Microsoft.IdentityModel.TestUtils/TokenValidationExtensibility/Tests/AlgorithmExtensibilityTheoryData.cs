// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class AlgorithmExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal AlgorithmExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            AlgorithmValidationDelegate algorithmValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
            };

            ValidationParameters.AlgorithmValidator = algorithmValidationDelegate;
            ValidationParameters.SignatureValidator = null;
            ValidationParameters.IssuerSigningKeys.Add(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key);
        }
    }
}
#nullable restore
