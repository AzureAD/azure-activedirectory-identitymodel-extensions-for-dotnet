// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JwsSignatureTests
    {
        [Theory, MemberData(nameof(InvalidSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidSignature(ValidateSignatureTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidSignature", theoryData);

            try
            {
                ValidationResult<SecurityKey, ValidationError> validationResult =
                    JsonWebTokenHandler.ValidateSignature(
                        theoryData.JwtToken,
                        theoryData.ValidationParameters,
                        theoryData.Configuration,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.AddDiff($"Expected test to fail, test succeeded (ValidationResult): TestId: {theoryData.TestId}, Result: {validationResult.Result}.");
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
                // We should never throw out of ValidateSignature.
                context.AddDiff($"JsonWebTokenHandler.ValidateSignature returning ValidationResult, should not throw exception caught: {ex}, TestId: {theoryData.TestId}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignatureTheoryData> InvalidSignatureTestCases
        {
            get
            {
                var unsignedToken = new JsonWebToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");

                TheoryData<ValidateSignatureTheoryData> theoryData = new TheoryData<ValidateSignatureTheoryData>();

                theoryData.Add(
                    new ValidateSignatureTheoryData("Null_JWT")
                    {
                        JwtToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "jwtToken"),
                            ValidationFailureType.NullArgument,
                            null)
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("Null_ValidationParameters")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "validationParameters"),
                            ValidationFailureType.NullArgument,
                            null)
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("DelegateReturnsFailure")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => new SignatureValidationError(
                                new MessageDetail("IDX10000: NullArgument", null),
                                ValidationFailureType.NullArgument,
                                ValidationError.GetCurrentStackFrame())
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "NullArgument"),
                            ValidationFailureType.NullArgument,
                            null)
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("NoKeys")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10527:"),
                        ValidationResult = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10500),
                            SignatureValidationFailure.SigningKeyNotFound,
                            null)
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidSignature(ValidateSignatureTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidSignature", theoryData);

            try
            {
                ValidationResult<SecurityKey, ValidationError> validationResult =
                    JsonWebTokenHandler.ValidateSignature(
                        theoryData.JwtToken,
                        theoryData.ValidationParameters,
                        theoryData.Configuration,
                        theoryData.CallContext);

                if (!validationResult.Succeeded)
                {
                    context.AddDiff($"Expected test to succeeded, test failed (ValidationResult): TestId: {theoryData.TestId}, Error: {validationResult.Error!.GetException()}.");
                }
                else
                {
                    IdentityComparer.AreSecurityKeysEqual(
                        validationResult.Result,
                        theoryData.ValidationResult.Result,
                        context);
                }
            }
            catch (Exception ex)
            {
                // We should never throw out of ValidateSignature.
                context.AddDiff($"JsonWebTokenHandler.ValidateSignature returning ValidationResult, should not throw exception caught: {ex}, TestId: {theoryData.TestId}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignatureTheoryData> ValidSignatureTestCases
        {
            get
            {
                TheoryData<ValidateSignatureTheoryData> theoryData = new TheoryData<ValidateSignatureTheoryData>();

                var unsignedToken = new JsonWebToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");

                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
                theoryData.Add(
                    new ValidateSignatureTheoryData("DelegateReturnsToken")
                    {
                        JwtToken = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => KeyingMaterial.JsonWebKeyRsa256PublicSigningCredentials.Key
                        },

                        ValidationResult = KeyingMaterial.JsonWebKeyRsa256PublicSigningCredentials.Key
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("KidMatches")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
                            })),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]),
                        ValidationResult = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("X5tMatches")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2
                            })),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(signingKeys: [KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Key]),
                        ValidationResult = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Key,
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("SigningKeyResolverKeyMatches")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
                            })),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureKeyResolver = (token, securityToken, kid, validationParameters, configuration, callContext) =>
                                KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key
                        },
                        ValidationResult = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("ConfurationKeyMatches")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
                            })),
                        Configuration = ValidationUtils.CreateOpenIdConntectConfiguration(signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]),
                        ValidationParameters = new ValidationParameters(),
                        ValidationResult = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                    });

                theoryData.Add(
                    new ValidateSignatureTheoryData("NoKeyId_TryAllKeys")
                    {
                        JwtToken = new JsonWebToken(jsonWebTokenHandler.CreateToken(
                            new SecurityTokenDescriptor
                            {
                                SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId
                            })),
                        ValidationParameters = ValidationUtils.CreateValidationParameters(signingKeys: [KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key]),
                        ValidationResult = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key,
                    });

                return theoryData;
            }
        }
    }
}
