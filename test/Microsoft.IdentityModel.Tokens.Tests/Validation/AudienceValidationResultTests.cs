// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;
using System.Collections.Generic;
using Microsoft.IdentityModel.Abstractions;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AudienceValidationResultTests
    {
        [Theory, MemberData(nameof(ValidateAudienceTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateAudienceParameters(AudienceValidationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.AudienceValidatorResultTests", theoryData);

            if (theoryData.AudiencesToAdd != null)
            {
                foreach (string audience in theoryData.AudiencesToAdd)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            Result<string, ExceptionDetail> result = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreStringsEqual(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                Exception exception = result.UnwrapError().GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AudienceValidationTheoryData> ValidateAudienceTestCases
        {
            get
            {
                var audience1 = "http://audience1.com";
                var audience2 = "http://audience2.com";
                List<string> audiences1 = new List<string> { "", audience1 };
                List<string> audiences1WithSlash = new List<string> { "", audience1 + "/" };
                List<string> audiences1WithTwoSlashes = new List<string> { "", audience1 + "//" };
                List<string> audiences2 = new List<string> { "", audience2 };
                List<string> audiences2WithSlash = new List<string> { "", audience2 + "/" };

                var commaAudience1 = ", " + audience1;
                var commaAudience2 = ", " + audience2;
                var audience1Slash = audience1 + "/";
                var audience2Slash = audience2 + "/";
                var commaAudience1Slash = commaAudience1 + "/";
                var commaAudience2Slash = commaAudience2 + "/";

                return new TheoryData<AudienceValidationTheoryData>
                {
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "Invalid_ValidationParametersIsNull",
                        ValidationParameters = null,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationErrorType.ArgumentNull,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = null,
                        TestId = "Invalid_AudiencesIsNull",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10207:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(LogMessages.IDX10207),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string>{ },
                        TestId = "Invalid_AudiencesIsEmptyList",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                        ValidationParameters = new ValidationParameters(),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10206,
                                null),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        TestId = "Invalid_ValidAudiencesIsEmptyString",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [String.Empty],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII(String.Empty)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        TestId = "Invalid_ValidAudiencesIsWhiteSpace",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = ["    "],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII("    ")),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Valid_SameLengthMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = audience1
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_SameLengthNotMatched",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_AudiencesValidAudienceWithSlashNotMatched",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2 + "/"],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2Slash)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences2WithSlash,
                        TestId = "Invalid_AudiencesWithSlashValidAudienceSameLengthNotMatched",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudienceWithSlash_IgnoreTrailingSlashFalse",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1 + "/"],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1Slash)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Valid_ValidAudienceWithSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "/"],
                        Result = audience1
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = audiences1WithSlash,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1Slash)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Valid_ValidAudiencesWithSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithSlash,
                        Result = audience1
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudienceWithExtraChar",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "A"],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "A")),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudienceWithDoubleSlash_IgnoreTrailingSlashTrue",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "//"],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "//")),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudiencesWithDoubleSlash_IgnoreTrailingSlashTrue",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithTwoSlashes,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1 + "//")),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Invalid_TokenAudienceWithSlash_IgnoreTrailingSlashFalse",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Valid_TokenAudienceWithSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences2WithSlash,
                        TestId = "Invalid_TokenAudienceWithSlashNotEqual",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Invalid_TokenAudiencesWithSlash_IgnoreTrailingSlashFalse",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Valid_TokenAudiencesWithSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Invalid_TokenAudiencesWithSlashValidAudiencesNotMatched_IgnoreTrailingSlashTrue",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences2,
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(commaAudience2)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithTwoSlashes,
                        TestId = "TokenAudienceWithTwoSlashesVPTrue",
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1 + "//"),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            null,
                            null)
                    }
                };
            }
        }

        public class AudienceValidationTheoryData : TheoryDataBase
        {
            public List<string> Audiences { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; } = new ValidationParameters();

            internal ValidationFailureType ValidationFailureType { get; set; }

            public List<string> AudiencesToAdd { get; internal set; }

            internal Result<string, ExceptionDetail> Result { get; set; }
        }


    }
}
