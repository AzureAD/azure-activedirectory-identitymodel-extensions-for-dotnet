// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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

            ValidationResult<ValidatedSigningKeyLifetime> result = Validators.ValidateIssuerSigningKey(
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

                theoryData.ExpectedException.ProcessNoException();
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
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidationError(
                            new MessageDetail(LogMessages.IDX10253),
                            ValidationFailureType.SigningKeyValidationFailed,
                            typeof(ArgumentNullException),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000:"),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = null,
                        ValidationParameters = new ValidationParameters (),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_ValidationParametersIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000:"),
                        SecurityKey = KeyingMaterial.SymmetricSecurityKey2_256,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = null,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsExpired",
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10249:"),
                        SecurityKey = KeyingMaterial.ExpiredX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10249,
                                LogHelper.MarkAsNonPII(utcExpired),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.SigningKeyValidationFailed,
                            typeof(SecurityTokenInvalidSigningKeyException),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNotYetValid",
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException(substringExpected: "IDX10248:"),
                        SecurityKey = KeyingMaterial.NotYetValidX509SecurityKey_Public,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10248,
                                LogHelper.MarkAsNonPII(utcNotYetValid),
                                LogHelper.MarkAsNonPII(utcNow)),
                            ValidationFailureType.SigningKeyValidationFailed,
                            typeof(SecurityTokenInvalidSigningKeyException),
                            null),
                    },
                    new SigningKeyValidationTheoryData
                    {
                        TestId = "Invalid_SecurityKeyIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10253:"),
                        SecurityKey = null,
                        SecurityToken = new JwtSecurityToken(),
                        ValidationParameters = new ValidationParameters (),
                        Result = new ValidationError(
                            new MessageDetail(LogMessages.IDX10253),
                            ValidationFailureType.SigningKeyValidationFailed,
                            typeof(ArgumentNullException),
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
        internal ValidationResult<ValidatedSigningKeyLifetime> Result { get; set; }
    }
}
