// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Xunit;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class TokenTypeValidationResultTests
    {
        [Theory, MemberData(nameof(TokenTypeValidationTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateTokenType(TokenTypeTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.TokenTypeValidationResultTests", theoryData);

            if (theoryData.TokenTypesToAdd != null)
            {
                foreach (string tokenType in theoryData.TokenTypesToAdd)
                    theoryData.ValidationParameters.ValidTypes.Add(tokenType);
            }

            Result<ValidatedTokenType> result = Validators.ValidateTokenType(
                theoryData.Type,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreValidatedTokenTypesEqual(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException();
            }
            else
            {
                ExceptionDetail exceptionDetail = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    exceptionDetail.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = exceptionDetail.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);

        }

        public static TheoryData<TokenTypeTheoryData> TokenTypeValidationTestCases
        {
            get
            {
                String[] validTypesNoJwt = { "ID Token", "Refresh Token", "Access Token" };
                String[] validTypesWithJwt = { "ID Token", "Refresh Token", "Access Token", "JWT" };

                return new TheoryData<TokenTypeTheoryData>
                {
                    new TokenTypeTheoryData
                    {
                        TestId = "Valid_DefaultTokenTypeValidation",
                        Type = "JWT",
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, "JWT"),
                        ValidationParameters = new ValidationParameters(),
                        TokenTypesToAdd = validTypesWithJwt,
                        Result = new ValidatedTokenType("JWT", 4)
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Type = "JWT",
                        SecurityToken = null,
                        ValidationParameters = null,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("securityToken")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null,
                            null)
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_ValidationParametersAreNull",
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Type = "JWT",
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, "JWT"),
                        ValidationParameters = null,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null,
                            null)
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_TokenTypeIsEmpty",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10256:"),
                        Type = String.Empty,
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, String.Empty),
                        ValidationParameters = new ValidationParameters(),
                        TokenTypesToAdd = validTypesNoJwt,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10256,
                                LogHelper.MarkAsNonPII("type")),
                            ValidationFailureType.TokenTypeValidationFailed,
                            typeof(SecurityTokenInvalidTypeException),
                            null,
                            null)
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_TokenTypeIsNull",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10256:"),
                        Type = null,
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, null),
                        ValidationParameters = new ValidationParameters(),
                        TokenTypesToAdd = validTypesNoJwt,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10256,
                                LogHelper.MarkAsNonPII("type")),
                            ValidationFailureType.TokenTypeValidationFailed,
                            typeof(SecurityTokenInvalidTypeException),
                            null,
                            null)
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_ValidationParametersValidTypesDoesNotSupportType",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10257:"),
                        Type = "JWT",
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, "JWT"),
                        ValidationParameters = new ValidationParameters(),
                        TokenTypesToAdd = validTypesNoJwt,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10257,
                                LogHelper.MarkAsNonPII("type"),
                                LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validTypesNoJwt))),
                            ValidationFailureType.TokenTypeValidationFailed,
                            typeof(SecurityTokenInvalidTypeException),
                            null,
                            null)
                    }
                };
            }
        }

        public class TokenTypeTheoryData : TheoryDataBase
        {
            public string Type { get; set; }

            public SecurityToken SecurityToken { get; set; }
            public IList<string> TokenTypesToAdd { get; internal set; }
            internal ValidationParameters ValidationParameters { get; set; }
            internal Result<ValidatedTokenType> Result { get; set; }
        }
    }
}
