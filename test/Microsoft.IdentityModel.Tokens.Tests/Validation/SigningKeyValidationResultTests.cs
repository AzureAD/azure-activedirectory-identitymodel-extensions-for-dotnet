// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Abstractions;
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

            Result<ValidatedSigningKeyLifetime, TokenValidationError> result = Validators.ValidateIssuerSigningKey(
                theoryData.SecurityKey,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                theoryData.BaseConfiguration,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreValidatedSigningKeyLifetimesEqual(
                    theoryData.Result.UnwrapResult(),
                    result.UnwrapResult(),
                    context);
            }
            else
            {
                IdentityComparer.AreTokenValidationErrorsEqual(
                    result.UnwrapError(),
                    theoryData.Result.UnwrapError(),
                    context);

                if (result.UnwrapError().InnerException is not null)
                    theoryData.ExpectedException.ProcessException(result.UnwrapError().InnerException);
                else
                    theoryData.ExpectedException.ProcessNoException();
            }

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
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidatedSigningKeyLifetime(null, null, utcNow)
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNull",
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(),
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(LogMessages.IDX10253),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters (),
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_ValidationParametersIsNull",
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = null,
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsExpired",
                        SecurityKey = KeyingMaterial.ExpiredX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidSigningKey,
                            new MessageDetail(
                                LogMessages.IDX10249,
                                LogHelper.MarkAsNonPII(utcExpired),
                                LogHelper.MarkAsNonPII(utcNow)),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNotYetValid",
                        SecurityKey = KeyingMaterial.NotYetValidX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidSigningKey,
                            new MessageDetail(
                                LogMessages.IDX10248,
                                LogHelper.MarkAsNonPII(utcNotYetValid),
                                LogHelper.MarkAsNonPII(utcNow)),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(LogMessages.IDX10253),
                            null),
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
        internal Result<ValidatedSigningKeyLifetime, TokenValidationError> Result { get; set; }
    }
}
