// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidateSignatureTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerValidateSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateSignature(JsonWebTokenHandlerValidateSignatureTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateSignature", theoryData);
            JsonWebToken jsonWebToken;
            if (theoryData.JWT == null && theoryData.SigningCredentials != null)
            {
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    SigningCredentials = theoryData.SigningCredentials,
                };
                var tokenHandler = new JsonWebTokenHandler();
                jsonWebToken = new JsonWebToken(tokenHandler.CreateToken(tokenDescriptor));
            }
            else
                jsonWebToken = theoryData.JWT;


            if (theoryData.Configuration is not null && theoryData.KeyToAddToConfiguration is not null)
                theoryData.Configuration.SigningKeys.Add(theoryData.KeyToAddToConfiguration);

            if (theoryData.ValidationParameters is not null && theoryData.KeyToAddToValidationParameters is not null)
                theoryData.ValidationParameters.IssuerSigningKeys.Add(theoryData.KeyToAddToValidationParameters);

            ValidationResult<TokenValidationUnit> result = JsonWebTokenHandler.ValidateSignature(
                jsonWebToken,
                theoryData.ValidationParameters,
                theoryData.Configuration,
                new CallContext
                {
                    DebugId = theoryData.TestId
                });

            if (result.IsSuccess)
            {
                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                ValidationError validationError = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    validationError.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = validationError.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebTokenHandlerValidateSignatureTheoryData> JsonWebTokenHandlerValidateSignatureTestCases
        {
            get
            {
                var unsignedToken = new JsonWebToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.");
                return new TheoryData<JsonWebTokenHandlerValidateSignatureTheoryData>
                {
                    new JsonWebTokenHandlerValidateSignatureTheoryData {
                        TestId = "Invalid_Null_JWT",
                        JWT = null,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "jwtToken"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData {
                        TestId = "Invalid_Null_ValidationParameters",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "validationParameters"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData {
                        TestId = "Invalid_DelegateReturnsFailure",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => ValidationError.NullParameter("fakeParameter", null)
                        },
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                "fakeParameter"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoSignature",
                        JWT = unsignedToken,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10504,
                                LogHelper.MarkAsSecurityArtifact(unsignedToken, JwtTokenUtilities.SafeLogJwtToken)),
                            ValidationFailureType.SignatureValidationFailed,
                            typeof(SecurityTokenInvalidSignatureException),
                            null)
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_DelegateReturnsSuccess",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => TokenValidationUnit.Default
                        },
                        Result = KeyingMaterial.JsonWebKeyRsa256PublicSigningCredentials.Key
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_SignatureValidationResult_Success_KidMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        ValidationParameters = new ValidationParameters(),
                        KeyToAddToValidationParameters = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                        Result = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_SignatureValidationResult_Success_X5tMatches",
                        SigningCredentials = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2,
                        ValidationParameters = new ValidationParameters(),
                        KeyToAddToValidationParameters = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Key,
                        Result = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Key,
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_IssuerSigningKeyResolverReturnsKeyThatMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters, configuration, callContext) => KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key
                        },
                        Result = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_ConfurationReturnsKeyThatMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Configuration = new OpenIdConnectConfiguration(),
                        KeyToAddToConfiguration = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                        ValidationParameters = new ValidationParameters(),
                        Result = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_NoKeyId_TryAllKeys",
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ValidationParameters = new ValidationParameters
                        {
                            TryAllIssuerSigningKeys = true
                        },
                        KeyToAddToValidationParameters = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key,
                        Result = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key,
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoKeyId_DontTryAllKeys",
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ValidationParameters = new ValidationParameters(),
                        KeyToAddToValidationParameters = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                        Result = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10500),
                            ValidationFailureType.SignatureValidationFailed,
                            typeof(SecurityTokenSignatureKeyNotFoundException),
                            null)
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoKeys",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10502:"),
                        Result = new ValidationError(
                            new MessageDetail(TokenLogMessages.IDX10500),
                            ValidationFailureType.SignatureValidationFailed,
                            typeof(SecurityTokenSignatureKeyNotFoundException),
                            null)
                    }
                };
            }
        }
    }

    public class JsonWebTokenHandlerValidateSignatureTheoryData : TheoryDataBase
    {
        public JsonWebToken JWT { get; set; }
        public BaseConfiguration Configuration { get; set; }
        public SigningCredentials SigningCredentials { get; internal set; }
        public SecurityKey KeyToAddToConfiguration { get; internal set; }
        public SecurityKey KeyToAddToValidationParameters { get; internal set; }
        internal ValidationResult<SecurityKey> Result { get; set; }
        internal ValidationParameters ValidationParameters { get; set; }
    }
}
