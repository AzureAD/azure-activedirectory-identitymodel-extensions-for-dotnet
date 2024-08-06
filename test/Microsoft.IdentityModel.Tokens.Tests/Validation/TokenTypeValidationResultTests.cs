// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class TokenTypeValidationResultTests
    {
        [Theory, MemberData(nameof(TokenTypeValidationTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateTokenType(TokenTypeTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.TokenTypeValidationResultTests", theoryData);

            TokenTypeValidationResult tokenTypeValidationResult = Validators.ValidateTokenType(
                theoryData.Type,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (tokenTypeValidationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(tokenTypeValidationResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

            IdentityComparer.AreTokenTypeValidationResultsEqual(
                tokenTypeValidationResult,
                theoryData.TokenTypeValidationResult,
                context);

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
                        ValidationParameters = new ValidationParameters
                        {
                            ValidTypes = validTypesWithJwt
                        },
                        TokenTypeValidationResult = new TokenTypeValidationResult("JWT")
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_SecurityTokenIsNull",
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Type = "JWT",
                        SecurityToken = null,
                        ValidationParameters = null,
                        TokenTypeValidationResult = new TokenTypeValidationResult(
                            "JWT",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("securityToken")),
                                typeof(ArgumentNullException),
                                new StackFrame(true)))
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_ValidationParametersAreNull",
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Type = "JWT",
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, "JWT"),
                        ValidationParameters = null,
                        TokenTypeValidationResult = new TokenTypeValidationResult(
                            "JWT",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("validationParameters")),
                                typeof(ArgumentNullException),
                                new StackFrame(true)))
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_TokenTypeIsEmpty",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10256:"),
                        Type = String.Empty,
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, String.Empty),
                        ValidationParameters = new ValidationParameters
                        {
                            ValidTypes = validTypesNoJwt
                        },
                        TokenTypeValidationResult = new TokenTypeValidationResult(
                            string.Empty,
                            ValidationFailureType.TokenTypeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10256,
                                    LogHelper.MarkAsNonPII("type")),
                                typeof(SecurityTokenInvalidTypeException),
                                new StackFrame(true)))
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_TokenTypeIsNull",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10256:"),
                        Type = null,
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, null),
                        ValidationParameters = new ValidationParameters
                        {
                            ValidTypes = validTypesNoJwt
                        },
                        TokenTypeValidationResult = new TokenTypeValidationResult(
                            null,
                            ValidationFailureType.TokenTypeValidationFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10256,
                                    LogHelper.MarkAsNonPII("type")),
                                typeof(SecurityTokenInvalidTypeException),
                                new StackFrame(true)))
                    },
                    new TokenTypeTheoryData
                    {
                        TestId = "Invalid_ValidationParametersValidTypesDoesNotSupportType",
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10257:"),
                        Type = "JWT",
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Typ, "JWT"),
                        ValidationParameters = new ValidationParameters
                        {
                            ValidTypes = validTypesNoJwt
                        },
                        TokenTypeValidationResult = new TokenTypeValidationResult(
                            "JWT",
                            ValidationFailureType.TokenTypeValidationFailed,
                            new ExceptionDetail(
                                 new MessageDetail(
                                     LogMessages.IDX10257,
                                     LogHelper.MarkAsNonPII("type"),
                                     LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validTypesNoJwt))),
                                 typeof(SecurityTokenInvalidTypeException),
                                 new StackFrame(true)))
                    }
                };
            }
        }

        public class TokenTypeTheoryData : TheoryDataBase
        {
            public string Type { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; }

            internal TokenTypeValidationResult TokenTypeValidationResult { get; set; }
        }
    }
}
