// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.JsonWebTokens.Results;
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

            SignatureValidationResult validationResult = JsonWebTokenHandler.ValidateSignature(
            jsonWebToken,
            theoryData.ValidationParameters,
            theoryData.Configuration,
            new CallContext());

            if (validationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(validationResult.Exception);
            else
                theoryData.ExpectedException?.ProcessNoException();

            IdentityComparer.AreSignatureValidationResultsEqual(validationResult, theoryData.SignatureValidationResult, context);
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
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10000,
                                    "jwtToken"),
                                typeof(ArgumentNullException),
                                new System.Diagnostics.StackFrame()))
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData {
                        TestId = "Invalid_Null_ValidationParameters",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10000,
                                    "validationParameters"),
                                typeof(ArgumentNullException),
                                new System.Diagnostics.StackFrame()))
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData {
                        TestId = "Invalid_DelegateReturnsFailure",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => SignatureValidationResult.NullParameterFailure("fakeParameter")
                        },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10000,
                                    "fakeParameter"),
                                typeof(ArgumentNullException),
                                new System.Diagnostics.StackFrame()))
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoSignature",
                        JWT = unsignedToken,
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10504,
                                    LogHelper.MarkAsSecurityArtifact(unsignedToken, JwtTokenUtilities.SafeLogJwtToken)),
                                typeof(SecurityTokenInvalidSignatureException),
                                new System.Diagnostics.StackFrame()))
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_DelegateReturnsSuccess",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters
                        {
                            SignatureValidator = (token, parameters, configuration, callContext) => new SignatureValidationResult()
                        },
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_SignatureValidationResult_Success_KidMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
                        },
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_SignatureValidationResult_Success_X5tMatches",
                        SigningCredentials = KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeys = [KeyingMaterial.X509SigningCreds_1024_RsaSha2_Sha2.Key]
                        },
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_IssuerSigningKeyResolverReturnsKeyThatMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters, configuration, callContext) => KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key
                        },
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_ConfurationReturnsKeyThatMatches",
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Configuration = new OpenIdConnectConfiguration(),
                        KeyToAddToConfiguration = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                        ValidationParameters = new ValidationParameters(),
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Valid_NoKeyId_TryAllKeys",
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeys = [KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key],
                            TryAllIssuerSigningKeys = true
                        },
                        SignatureValidationResult = new SignatureValidationResult()
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoKeyId_DontTryAllKeys",
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ValidationParameters = new ValidationParameters
                        {
                            IssuerSigningKeys = [KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId.Key],
                        },
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(TokenLogMessages.IDX10500),
                                typeof(SecurityTokenSignatureKeyNotFoundException),
                                new System.Diagnostics.StackFrame()))
                    },
                    new JsonWebTokenHandlerValidateSignatureTheoryData
                    {
                        TestId = "Invalid_NoKeys",
                        JWT = new JsonWebToken(EncodedJwts.LiveJwt),
                        ValidationParameters = new ValidationParameters(),
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                        SignatureValidationResult = new SignatureValidationResult(
                            ValidationFailureType.SignatureValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(TokenLogMessages.IDX10500),
                                typeof(SecurityTokenSignatureKeyNotFoundException),
                                new System.Diagnostics.StackFrame()))
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
        internal SignatureValidationResult SignatureValidationResult { get; set; }
        internal ValidationParameters ValidationParameters { get; set; }
    }
}
