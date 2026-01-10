// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

#if NET472_OR_GREATER || NET6_0_OR_GREATER
using System.Collections.Generic;
#endif
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JweDecryptionTests
    {
        [Theory, MemberData(nameof(InvalidDecryptTestCases), DisableDiscoveryEnumeration = false)]
        public void InvalidDecryptToken(ValidateEncryptionTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidDecryptToken", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            try
            {
                ValidationResult<string, ValidationError> validationResult =
                    jsonWebTokenHandler.DecryptToken(
                        theoryData.JwtToken,
                        theoryData.ValidationParameters,
                        theoryData.Configuration,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Decryption succeeded, expected to fail: {theoryData.TestId}.");
                }
                else
                {
                    ValidationError validationError = validationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.ValidationResult.Error.FailureType.Name,
                        context);

                    Exception exception = validationError.GetException();
                    theoryData.ExpectedException.ProcessException(exception, context);
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"Decryption threw: {ex.Message}, Methods returning ValidationResult should not throw: {theoryData.TestId}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateEncryptionTheoryData> InvalidDecryptTestCases
        {
            get
            {
                TheoryData<ValidateEncryptionTheoryData> theoryData = new TheoryData<ValidateEncryptionTheoryData>();

                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

                theoryData.Add(
                    new ValidateEncryptionTheoryData("AlgorithmMismatch_DecryptionFails")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                                EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                                Claims = Default.PayloadDictionary
                            })),
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            decryptionKeys: [KeyingMaterial.RsaSecurityKey_2048]),
                        ValidationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10609,
                                LogHelper.MarkAsSecurityArtifact(
                                    new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                                    JwtTokenUtilities.SafeLogJwtToken)),
                            ValidationFailureType.KeyWrapFailed,
                            null),
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("KeyIdMismatch_TryAllDecryptionKeysFalse_DecryptionFails")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                                EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                                Claims = Default.PayloadDictionary
                            })),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                        ValidationParameters = new ValidationParameters
                        {
                            TryAllDecryptionKeys = false,
                        },
                        Configuration = new CustomConfiguration(
                            new RsaSecurityKey(KeyingMaterial.RsaParameters_2048)
                            {
                                KeyId = "CustomRsaSecurityKey_2048"
                            }),
                        ValidationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10609,
                                LogHelper.MarkAsSecurityArtifact(
                                    new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                                    JwtTokenUtilities.SafeLogJwtToken)),
                            ValidationFailureType.TokenDecryptionFailed,
                            null),
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ParameterChecksTestCases), DisableDiscoveryEnumeration = false)]
        public void ParameterChecks(ValidateEncryptionTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ParameterChecks", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            try
            {
                ValidationResult<string, ValidationError> validationResult = jsonWebTokenHandler.DecryptToken(
                    theoryData.JwtToken,
                    theoryData.ValidationParameters,
                    theoryData.Configuration,
                    theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Decryption succeeded, expected to fail: {theoryData.TestId}.");
                }
                else
                {
                    ValidationError validationError = validationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.ValidationResult.Error.FailureType.Name,
                        context);

                    Exception exception = validationError.GetException();
                    theoryData.ExpectedException.ProcessException(exception, context);
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"Decryption threw: {ex.Message}, Should not throw: {theoryData.TestId}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateEncryptionTheoryData> ParameterChecksTestCases
        {
            get
            {
                TheoryData<ValidateEncryptionTheoryData> theoryData = new TheoryData<ValidateEncryptionTheoryData>();

                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

                theoryData.Add(
                    new ValidateEncryptionTheoryData("SecurityTokenIsNull")
                    {
                        JwtToken = null,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10000, "jwtToken"),
                            ValidationFailureType.NullArgument,
                            null),
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("ValidationParametersIsNull")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10000, "validationParameters"),
                            ValidationFailureType.NullArgument,
                            null),
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("TokenIsNotEncrypted")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10612:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10612),
                            ValidationFailureType.TokenDecryptionFailed,
                            null),
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidDecryptTestCases), DisableDiscoveryEnumeration = false)]
        public void ValidDecryptToken(ValidateEncryptionTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidDecryptToken", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            ValidationResult<string, ValidationError> validationResult = jsonWebTokenHandler.DecryptToken(
                theoryData.JwtToken,
                theoryData.ValidationParameters,
                theoryData.Configuration,
                theoryData.CallContext);

            try
            {
                if (!validationResult.Succeeded)
                {
                    context.AddDiff($"Decryption failed: {validationResult.Error}, Expected to succeed.");
                }
                else
                {
                    IdentityComparer.AreStringsEqual(
                        validationResult.Result,
                        theoryData.ValidationResult.Result,
                        context);

                    theoryData.ExpectedException.ProcessNoException(context);
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"Decryption threw: {ex.Message}, Expected to succeed.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateEncryptionTheoryData> ValidDecryptTestCases
        {
            get
            {
                TheoryData<ValidateEncryptionTheoryData> theoryData = new TheoryData<ValidateEncryptionTheoryData>();
                var validToken = EncodedJwts.LiveJwt;
                var token = new JsonWebToken(validToken);
                var jsonWebTokenHandler = new JsonWebTokenHandler();

                var rsaKey = new RsaSecurityKey(KeyingMaterial.RsaParameters_2048) { KeyId = "CustomRsaSecurityKey_2048" };
                var configurationThatThrows = CreateCustomConfigurationThatThrows(rsaKey);

                var configurationWithMismatchedKeys = new CustomConfiguration(rsaKey);

                theoryData.Add(
                    new ValidateEncryptionTheoryData("FromValidationParameters")
                    {
                        JwtToken = new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            decryptionKeys: [Default.SymmetricEncryptingCredentials.Key]),
                        ValidationResult = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("FromKeyResolver")
                    {
                        JwtToken = new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                        ValidationParameters = new ValidationParameters
                        {
                            DecryptionKeyResolver = (tokenString, token, kid, validationParameters, callContext) => [Default.SymmetricEncryptingCredentials.Key]
                        },
                        ValidationResult = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("FromConfiguration")
                    {
                        JwtToken = new JsonWebToken(ReferenceTokens.JWEDirectEncryptionUnsignedInnerJWTWithAdditionalHeaderClaims),
                        ValidationParameters = new ValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(new CustomConfiguration(Default.SymmetricEncryptingCredentials.Key))
                        },
                        Configuration = new CustomConfiguration(Default.SymmetricEncryptingCredentials.Key),
                        ValidationResult = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIyNTM0MDIzMDA3OTkifQ.",
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("OneKeyThrowsOnUnwrap")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                                EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                                Claims = Default.PayloadDictionary
                            })),
                        ValidationParameters = new ValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(configurationThatThrows)
                        },
                        Configuration = configurationThatThrows,
                        ValidationResult = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ikpzb25XZWJLZXlSc2FfMjA0OCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwOi8vRGVmYXVsdC5BdWRpZW5jZS5jb20iLCJhenAiOiJodHRwOi8vRGVmYXVsdC5BenAuY29tIiwiZW1haWwiOiJCb2JAY29udG9zby5jb20iLCJleHAiOiIyNTM0MDIzMDA3OTkiLCJnaXZlbl9uYW1lIjoiQm9iIiwiaXNzIjoiaHR0cDovL0RlZmF1bHQuSXNzdWVyLmNvbSIsImlhdCI6IjE0ODk3NzU2MTciLCJqdGkiOiJKdGkiLCJuYmYiOiIxNDg5Nzc1NjE3In0.Et69LAC4sn6nNm_HNz_AnJ8siLT6LRTjDSb1aY8APcwJmPn-TxU-8GG5_bmNkoVukR7hkYG2JuWPxJKbjDd73BlmelaiyZBoPUyU0S-GX3XgyC2v_CkOq4yYbtD-kq5s7kNNj5QJjZDq0oJeqcUMrq4xRWATPtUMkIZ0GpEhO_C5MFxT8jAWe_a2gyUA4KoibalKtkYgFvgLcvyZJhUx7AERbli6b7OkUksFp9zIwmc_jZZCXJ_F_wASyj9KgHQKN9VHER3bB2zQeWHR0q32ODYC4ggsan-Nkm-jIsATi2tgkKzROzK55dy8ZdFArXUYJRpI_raYkTUHRK_wP3GqtQ",
                    });

                theoryData.Add(
                    new ValidateEncryptionTheoryData("TryAllDecryptionKeys")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                                EncryptingCredentials = new EncryptingCredentials(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, SecurityAlgorithms.Aes128CbcHmacSha256),
                                Claims = Default.PayloadDictionary
                            })),
                        ValidationParameters = new ValidationParameters  // TryAllDecryptionKeys is true by default
                        {
                            ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(configurationWithMismatchedKeys)
                        },
                        Configuration = configurationWithMismatchedKeys,
                        ValidationResult = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ikpzb25XZWJLZXlSc2FfMjA0OCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwOi8vRGVmYXVsdC5BdWRpZW5jZS5jb20iLCJhenAiOiJodHRwOi8vRGVmYXVsdC5BenAuY29tIiwiZW1haWwiOiJCb2JAY29udG9zby5jb20iLCJleHAiOiIyNTM0MDIzMDA3OTkiLCJnaXZlbl9uYW1lIjoiQm9iIiwiaXNzIjoiaHR0cDovL0RlZmF1bHQuSXNzdWVyLmNvbSIsImlhdCI6IjE0ODk3NzU2MTciLCJqdGkiOiJKdGkiLCJuYmYiOiIxNDg5Nzc1NjE3In0.Et69LAC4sn6nNm_HNz_AnJ8siLT6LRTjDSb1aY8APcwJmPn-TxU-8GG5_bmNkoVukR7hkYG2JuWPxJKbjDd73BlmelaiyZBoPUyU0S-GX3XgyC2v_CkOq4yYbtD-kq5s7kNNj5QJjZDq0oJeqcUMrq4xRWATPtUMkIZ0GpEhO_C5MFxT8jAWe_a2gyUA4KoibalKtkYgFvgLcvyZJhUx7AERbli6b7OkUksFp9zIwmc_jZZCXJ_F_wASyj9KgHQKN9VHER3bB2zQeWHR0q32ODYC4ggsan-Nkm-jIsATi2tgkKzROzK55dy8ZdFArXUYJRpI_raYkTUHRK_wP3GqtQ",
                    });

#if NET472 || NET6_0_OR_GREATER
                var ecdsaEncryptingCredentials = new EncryptingCredentials(
                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                    SecurityAlgorithms.EcdhEsA256kw,
                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                };

                static IDictionary<string, object> AdditionalEcdhEsHeaderParameters(JsonWebKey publicKeySender)
                {
                    Dictionary<string, object> additionalHeaderParams = new Dictionary<string, object>()
                    {
                        { JwtHeaderParameterNames.Apu, Guid.NewGuid().ToString() },
                        { JwtHeaderParameterNames.Apv, Guid.NewGuid().ToString() },
                        { JwtHeaderParameterNames.Epk,
                            $"{{\"{JsonWebKeyParameterNames.Kty}\":\"{publicKeySender.Kty}\"," +
                            $"\"{JsonWebKeyParameterNames.Crv}\":\"{publicKeySender.Crv}\"," +
                            $"\"{JsonWebKeyParameterNames.X}\":\"{publicKeySender.X}\"," +
                            $"\"{JsonWebKeyParameterNames.Y}\":\"{publicKeySender.Y}\"}}" }
                    };

                    return additionalHeaderParams;
                }

                theoryData.Add(
                    new ValidateEncryptionTheoryData("Ecdh")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                EncryptingCredentials = ecdsaEncryptingCredentials,
                                Expires = DateTime.MaxValue,
                                NotBefore = DateTime.MinValue,
                                IssuedAt = DateTime.MinValue,
                                AdditionalHeaderClaims = AdditionalEcdhEsHeaderParameters(KeyingMaterial.JsonWebKeyP256_Public),
                            })),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(
                            decryptionKeys: [new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true)]
                        ),
                        ValidationResult = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjI1MzQwMjMwMDgwMCwiaWF0IjowLCJuYmYiOjB9."
                    });

#endif
                return theoryData;
            }
        }

        private static CustomConfiguration CreateCustomConfigurationThatThrows(SecurityKey rsaKey)
        {
            var customCryptoProviderFactory = new DerivedCryptoProviderFactory
            {
                IsSupportedAlgImpl = (alg, key) => true,
                CreateKeyWrapProviderForUnwrapImpl = (key, alg) => throw new InvalidOperationException("Test exception")
            };

            var sym512Hey = new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_512) { KeyId = "CustomSymmetricSecurityKey_512" };
            sym512Hey.CryptoProviderFactory = customCryptoProviderFactory;

            var configurationWithCustomCryptoProviderFactory = new CustomConfiguration(rsaKey);
            configurationWithCustomCryptoProviderFactory.TokenDecryptionKeys.Add(sym512Hey);

            return configurationWithCustomCryptoProviderFactory;
        }
    }

    public class CustomConfiguration : BaseConfiguration
    {
        public CustomConfiguration(SecurityKey tokenDecryptionKey) : base()
        {
            TokenDecryptionKeys.Add(tokenDecryptionKey);
        }
    }
}
