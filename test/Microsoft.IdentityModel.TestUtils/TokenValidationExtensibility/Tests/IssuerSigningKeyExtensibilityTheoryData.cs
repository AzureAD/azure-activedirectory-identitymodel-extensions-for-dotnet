// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public class IssuerSigningKeyExtensibilityTheoryData : ExtensibilityTheoryData
    {
        internal IssuerSigningKeyExtensibilityTheoryData(
            string testId,
            string tokenHandlerType,
            IssuerSigningKeyValidationDelegate issuerSigningKeyValidationDelegate,
            int extraStackFrames) : base(testId, tokenHandlerType, extraStackFrames)
        {
            var signingCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2;

            SecurityTokenDescriptor = new()
            {
                Issuer = Default.Issuer,
                SigningCredentials = signingCredentials,
            };

            ValidationParameters.IssuerSigningKeyValidator = issuerSigningKeyValidationDelegate;
            ValidationParameters.SignatureValidator = (SecurityToken token, ValidationParameters validationParameters, BaseConfiguration? configuration, CallContext callContext) =>
            {
                token.SigningKey = signingCredentials.Key;

                return signingCredentials.Key;
            };
        }
    }
}
#nullable restore
