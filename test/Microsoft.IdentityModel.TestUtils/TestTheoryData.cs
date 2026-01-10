// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace Microsoft.IdentityModel.TestUtils
{
    public class TestTheoryData
    {
        public static TheoryData<ValidateTokenReplayTheoryData> TokenReplayValidationTheoryData
        {
            get
            {
                return new TheoryData<ValidateTokenReplayTheoryData>
                {
                    new ValidateTokenReplayTheoryData("ValidateTokenReplay: false, TokenReplayValidator: null")
                    {
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorReturnsTrue)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsTrue
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorReturnsFalse)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsFalse,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:")
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorThrows)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorThrows,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("TokenReplayValidatorThrows")
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, TokenReplayValidator: null")
                    {
                        ValidateTokenReplay = true
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorReturnsTrue)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsTrue,
                        ValidateTokenReplay = true
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorReturnsFalse)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsFalse,
                        ValidateTokenReplay = true,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:")
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorThrows)}")
                    {
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorThrows,
                        ValidateTokenReplay = true,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("TokenReplayValidatorThrows")
                    }
                };
            }
        }

        public static TheoryData<ValidateTokenReplayTheoryData> CheckParametersForTokenReplayTheoryData
        {
            get
            {
                return new TheoryData<ValidateTokenReplayTheoryData>
                {
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorChecksExpirationTimeJwt)}")
                    {
                        Token = Default.AsymmetricJwt,
                        SecurityTokenHandler = new JwtSecurityTokenHandler(),
                        SigningKey = Default.AsymmetricSigningKey,
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorChecksExpirationTimeJwt,
                        ValidateTokenReplay = true
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorChecksExpirationTimeSaml)}")
                    {
                        Token = ReferenceTokens.SamlToken_Valid,
                        SecurityTokenHandler = new SamlSecurityTokenHandler(),
                        SigningKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorChecksExpirationTimeSaml,
                        ValidateTokenReplay = true,
                    },
                    new ValidateTokenReplayTheoryData($"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorChecksExpirationTimeSaml2)}")
                    {
                        Token = ReferenceTokens.Saml2Token_Valid,
                        SecurityTokenHandler = new Saml2SecurityTokenHandler(),
                        SigningKey = KeyingMaterial.DefaultAADSigningKey,
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorChecksExpirationTimeSaml2,
                        ValidateTokenReplay = true,
                    }
                };
            }
        }
    }
}
