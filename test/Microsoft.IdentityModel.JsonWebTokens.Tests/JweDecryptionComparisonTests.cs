// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

#if NET472 || NET6_0_OR_GREATER
using Newtonsoft.Json.Linq;
#endif

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    /// <summary>
    /// These tests validate the decryption of JWE's using both TokenValidationParameters and ValidationParameters.
    /// We want to make sure that they succeed or fail in the same way, and that the exceptions thrown are consistent.
    /// ValidationParameters path specific tests are written in DecryptTokenTests.
    /// The tests in these files could be merged however it is presumed that the TokenValidationParameters will remain fixed while
    /// ValidationParameters scenarios will evolve in the future, so it was chosen to keep them separate.
    /// </summary>
    public class JweDecryptionComparisonTests
    {
        [Theory, MemberData(nameof(InvalidDecryptionTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidDecryption(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidDecryption", theoryData);
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    theoryData.Token,
                    theoryData.TokenValidationParameters);

            try
            {
                // Validate the token using ValidationParameters
#pragma warning disable CS8604 // Possible null reference argument.
                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await jsonWebTokenHandler.ValidateTokenAsync(
                       theoryData.Token,
                       theoryData.ValidationParameters!,
                       theoryData.CallContext,
                       CancellationToken.None);
#pragma warning restore CS8604 // Possible null reference argument.

                if (tokenValidationResult.IsValid != validationResult.Succeeded)
                    context.AddDiff($"tokenValidationResult.IsValid: '{tokenValidationResult.IsValid}' != validationResult.Succeeded: '{validationResult.Succeeded}'.");

                if (tokenValidationResult.IsValid)
                    context.AddDiff($"Expected test to fail, test succeeded (TokenValidationResult): {theoryData.TestId}.");

                if (validationResult.Succeeded)
                    context.AddDiff($"Expected test to fail, test succeeded (ValidationResult): {theoryData.TestId}.");

                if (!tokenValidationResult.IsValid && !validationResult.Succeeded)
                {
                    // Verify the exception provided by the TokenValidationParameters path
                    theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);

                    // Verify the exception provided by the ValidationParameters path
                    theoryData.ExpectedExceptionValidationParameters.ProcessException(validationResult.Error!.GetException(), context);

                    // Exceptions
                    IdentityComparer.AreSecurityTokenExceptionsEqual(
                        tokenValidationResult.Exception,
                        validationResult.Error!.GetException(),
                        context);
                }
            }
            catch (Exception ex)
            {
                // If we get here, the test failed.
                context.AddDiff($"ValidateTokenAsync returning ValidationResult, should not throw exception caught: {ex}, TestId: {theoryData.TestId}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidDecryptionTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenTheoryData>();

                theoryData.Add(
                    new ValidateTokenTheoryData("NoDecryptionKeys")
                    {
                        Token = CreateEncryptedToken(
                            new EncryptingCredentials(
                                KeyingMaterial.DefaultX509Key_2048,
                                SecurityAlgorithms.RsaPKCS1,
                                SecurityAlgorithms.Aes128CbcHmacSha256)),
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                    });

                theoryData.Add(
                    new ValidateTokenTheoryData("WrongDecryptionKey")
                    {
                        Token = CreateEncryptedToken(
                            new EncryptingCredentials(
                                KeyingMaterial.DefaultX509Key_2048,
                                SecurityAlgorithms.RsaPKCS1,
                                SecurityAlgorithms.Aes128CbcHmacSha256)),
                        TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultRsaSecurityKey1),
                        ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultRsaSecurityKey1),
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                    });

                theoryData.Add(
                    new ValidateTokenTheoryData("OnTokenDecryptFailure_KeysOnlyInTvp_ThrowsException")
                    {
                        Token = CreateEncryptedToken(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            tokenDecryptionKey: KeyingMaterial.DefaultSymmetricSecurityKey_128,
                            configurationManager: new MockConfigurationManager<OpenIdConnectConfiguration>(
                                new OpenIdConnectConfiguration())),
                        ValidationParameters = CreateValidationParameters(
                            tokenDecryptionKey: KeyingMaterial.DefaultSymmetricSecurityKey_128,
                            configurationManager: new MockConfigurationManager<OpenIdConnectConfiguration>(
                                new OpenIdConnectConfiguration())),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:"),
                    });
                theoryData.Add(
                    new ValidateTokenTheoryData("OnTokenDecryptFailure_KeysOnlyInTvp_ThrowsException")
                    {
                        Token = CreateEncryptedToken(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            tokenDecryptionKey: new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_128),
                            configurationManager: new MockConfigurationManager<OpenIdConnectConfiguration>(
                                new OpenIdConnectConfiguration())),
                        ValidationParameters = CreateValidationParameters(
                            tokenDecryptionKey: new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_128),
                            configurationManager: new MockConfigurationManager<OpenIdConnectConfiguration>(
                                new OpenIdConnectConfiguration())),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenDecryptionFailedException("IDX10603:"),
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidDecryptionTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidDecryption(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidDecryption", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    theoryData.Token,
                    theoryData.TokenValidationParameters);

            // Validate the token using ValidationParameters
#pragma warning disable CS8604 // Possible null reference argument.
            ValidationResult<ValidatedToken, ValidationError> validationResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    theoryData.Token,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);
#pragma warning restore CS8604 // Possible null reference argument.

            if (tokenValidationResult.IsValid != validationResult.Succeeded)
                context.AddDiff($"tokenValidationResult.IsValid: '{tokenValidationResult.IsValid}' != ValidationResult.Succeeded: '{validationResult.Succeeded}', TestId: {theoryData.TestId}.");

            if (!tokenValidationResult.IsValid)
                context.AddDiff($"Expected test to succeeded, test failed (TokenValidationResult): TestId: {theoryData.TestId}.");

            if (!validationResult.Succeeded)
            {
                context.AddDiff($"Expected test to succeeded, test failed (ValidationResult): TestId: {theoryData.TestId}, Error: {validationResult.Error!.GetException()}.");
            }

            if (tokenValidationResult.IsValid && validationResult.Succeeded)
            {
                // ClaimsIdentity
                IdentityComparer.AreEqual(
                    tokenValidationResult.ClaimsIdentity,
                    validationResult.Result!.ClaimsIdentity,
                    context);

                // Claims
                IdentityComparer.AreEqual(
                    tokenValidationResult.Claims,
                    validationResult.Result!.Claims,
                    context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidDecryptionTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenTheoryData>();

                theoryData.Add(
                    new ValidateTokenTheoryData("Aes128Cbc_HmacSha256")
                    {
                        Token = CreateEncryptedToken(
                            new EncryptingCredentials(
                                KeyingMaterial.DefaultX509Key_2048,
                                SecurityAlgorithms.RsaPKCS1,
                                SecurityAlgorithms.Aes128CbcHmacSha256)),
                        TokenValidationParameters = CreateTokenValidationParameters(KeyingMaterial.DefaultX509Key_2048),
                        ValidationParameters = CreateValidationParameters(KeyingMaterial.DefaultX509Key_2048),
                    });

#if NET472 || NET6_0_OR_GREATER
                theoryData.Add(
                    new ValidateTokenTheoryData("EcdhEs")
                    {
                        Token = CreateEncryptedToken(
                            new EncryptingCredentials(
                                new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                            {
                                KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP521_Public
                            },
                            AdditionalEcdhEsHeaderParameters(KeyingMaterial.JsonWebKeyP521_Public)),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521,
                            true)),
                        ValidationParameters = CreateValidationParameters(
                            new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521,
                            true)),
                    });
#endif
                theoryData.Add(
                    new ValidateTokenTheoryData("KeysInConfig_SuccessOnRetry")
                    {
                        Token = CreateEncryptedToken(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            configurationManager: CreateConfigurationManager(true)),
                        ValidationParameters = CreateValidationParameters(
                            configurationManager: CreateConfigurationManager(true)),
                    });

                theoryData.Add(
                    new ValidateTokenTheoryData("KeyWithoutKeyId_OnTokenDecryptFailure_KeysInConfig_SuccessOnRetry")
                    {
                        Token = CreateEncryptedToken(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            configurationManager: CreateConfigurationManager(false)),
                        ValidationParameters = CreateValidationParameters(
                            configurationManager: CreateConfigurationManager(false))
                    });

                return theoryData;
            }
        }

        private static string CreateEncryptedToken(
            EncryptingCredentials? encryptingCredentials,
            IDictionary<string, object>? additionalHeaderClaims = null)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                EncryptingCredentials = encryptingCredentials,
                AdditionalHeaderClaims = additionalHeaderClaims,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }

        private static TokenValidationParameters CreateTokenValidationParameters(
            SecurityKey? tokenDecryptionKey = null,
            bool tryAllKeys = false,
            BaseConfigurationManager? configurationManager = null)
        {
            // Skip all validations. We just want to decrypt the JWE.
            var tokenValidationParameters = new TokenValidationParameters
            {
                ConfigurationManager = configurationManager,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                ValidateIssuerSigningKey = false,
                RequireSignedTokens = false,
                TokenDecryptionKey = tokenDecryptionKey,
            };

            return tokenValidationParameters;
        }

        private static ValidationParameters CreateValidationParameters(
            SecurityKey? tokenDecryptionKey = null,
            BaseConfigurationManager? configurationManager = null)
        {
            ValidationParameters validationParameters = new ValidationParameters();

            if (tokenDecryptionKey != null)
                validationParameters.DecryptionKeys.Add(tokenDecryptionKey);

            validationParameters.ConfigurationManager = configurationManager;

            // Skip all validations. We just want to decrypt the JWE
            validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
            validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
            validationParameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
            validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
            validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
            validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
            validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
            validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

            return validationParameters;
        }

        private static BaseConfigurationManager CreateConfigurationManager(bool invalidKeyHasKeyId)
        {
            var configWrongDecryptKeys = new OpenIdConnectConfiguration();
            if (invalidKeyHasKeyId)
                configWrongDecryptKeys.TokenDecryptionKeys.Add(KeyingMaterial.DefaultSymmetricSecurityKey_128);
            else
                configWrongDecryptKeys.TokenDecryptionKeys.Add(new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_128) { KeyId = null });

            var configWithDecryptKeys = new OpenIdConnectConfiguration();
            configWithDecryptKeys.TokenDecryptionKeys.Add(KeyingMaterial.DefaultSymmetricSecurityKey_256);

            var configManager = new MockConfigurationManager<OpenIdConnectConfiguration>(configWrongDecryptKeys);
            configManager.RefreshedConfiguration = configWithDecryptKeys;

            return configManager;
        }

#if NET472 || NET6_0_OR_GREATER
        private static Dictionary<string, object> AdditionalEcdhEsHeaderParameters(JsonWebKey publicKeySender)
        {
            // Create the Ephemeral Public Key (Epk) header parameter as a JWK.
            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, publicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, publicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, publicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, publicKeySender.Y);

            // Set the Ephemeral Public Key (Epk) header parameter, along with the
            // Agreement PartyUInfo (Apu) and Agreement PartyVInfo (Apv) header parameters
            // to ensure that the ECDH-ES key agreement is successful.
            Dictionary<string, object> additionalHeaderParams = new Dictionary<string, object>()
                    {
                        { JsonWebTokens.JwtHeaderParameterNames.Apu, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Apv, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Epk, epkJObject.ToString(Newtonsoft.Json.Formatting.None) }
                    };

            return additionalHeaderParams;
        }
#endif
    }
}
#nullable restore
