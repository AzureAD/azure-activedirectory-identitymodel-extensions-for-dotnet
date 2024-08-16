// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class SigningKeyValidationResultTests
    {
        [Theory, MemberData(nameof(SigningKeyValidationTestCases), DisableDiscoveryEnumeration = true)]
        public void SecurityKey(SigningKeyValidationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.SigningKeyValidationResultTests", theoryData);

            SigningKeyValidationResult signingKeyValidationResult = Validators.ValidateIssuerSigningKey(
                theoryData.SecurityKey,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                theoryData.BaseConfiguration,
                new CallContext());

            if (signingKeyValidationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(signingKeyValidationResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

            IdentityComparer.AreSigningKeyValidationResultsEqual(
                signingKeyValidationResult,
                theoryData.SigningKeyValidationResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SigningKeyValidationTheoryData> SigningKeyValidationTestCases
        {
            get
            {
                DateTime utcNow = DateTime.UtcNow;
                DateTime utcExpired = KeyingMaterial.ExpiredX509SecurityKey_Public.Certificate.NotAfter.ToUniversalTime();
                DateTime utcNotYetValid = KeyingMaterial.NotYetValidX509SecurityKey_Public.Certificate.NotBefore.ToUniversalTime();

                return new TheoryData<SigningKeyValidationTheoryData>
                {
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Valid_SecurityTokenIsPresent",
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(),
                        SigningKeyValidationResult = new SigningKeyValidationResult(KeyingMaterial.SymmetricSecurityKey2_256)
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(),
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            null, // SecurityKey
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(LogMessages.IDX10253),
                                ExceptionDetail.ExceptionType.ArgumentNull))
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters (),
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            KeyingMaterial.SymmetricSecurityKey2_256,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("securityToken")),
                                ExceptionDetail.ExceptionType.ArgumentNull))
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_ValidationParametersIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = null,
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            KeyingMaterial.SymmetricSecurityKey2_256,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("validationParameters")),
                                ExceptionDetail.ExceptionType.ArgumentNull))
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsExpired",
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10249:"),
                        SecurityKey = KeyingMaterial.ExpiredX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            KeyingMaterial.ExpiredX509SecurityKey_Public,
                            ValidationFailureType.SigningKeyValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10249,
                                    LogHelper.MarkAsNonPII(utcExpired),
                                    LogHelper.MarkAsNonPII(utcNow)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidSigningKey))
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNotYetValid",
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10248:"),
                        SecurityKey = KeyingMaterial.NotYetValidX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            KeyingMaterial.NotYetValidX509SecurityKey_Public,
                            ValidationFailureType.SigningKeyValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10248,
                                    LogHelper.MarkAsNonPII(utcNotYetValid),
                                    LogHelper.MarkAsNonPII(utcNow)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidSigningKey))
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        SigningKeyValidationResult = new SigningKeyValidationResult(
                            null,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(LogMessages.IDX10253),
                                ExceptionDetail.ExceptionType.ArgumentNull))
                    },

                };
            }
        }
    }

    public class SigningKeyValidationTheoryData : TheoryDataBase
    {
        public SecurityKey SecurityKey { get; set; }
        public SecurityToken SecurityToken { get; set; }
        internal ValidationParameters ValidationParameters { get; set; }
        public BaseConfiguration BaseConfiguration { get; set; }
        internal SigningKeyValidationResult SigningKeyValidationResult { get; set; }
    }
}
