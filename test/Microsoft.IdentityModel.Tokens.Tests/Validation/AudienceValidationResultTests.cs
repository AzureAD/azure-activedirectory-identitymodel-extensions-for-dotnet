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

            Result<string, ITokenValidationError> result = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (result.IsSuccess)
                IdentityComparer.AreStringsEqual(
                    result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);
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

                TestUtilities.AssertFailIfErrors(context);
            }
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
                        TestId = "Invalid_ValidationParametersIsNull",
                        ValidationParameters = null,
                        Result = new TokenValidationError(
                            ValidationErrorType.ArgumentNull,
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = null,
                        TestId = "Invalid_AudiencesIsNull",
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10207,
                                null),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string>{ },
                        TestId = "Invalid_AudiencesIsEmptyList",
                        ValidationParameters = new ValidationParameters(),
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10206,
                                null),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        TestId = "Invalid_ValidAudiencesIsEmptyString",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [String.Empty],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII(String.Empty)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        TestId = "Invalid_ValidAudiencesIsWhiteSpace",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = ["    "],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII("    ")),
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
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_AudiencesValidAudienceWithSlashNotMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2 + "/"],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2Slash)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences2WithSlash,
                        TestId = "Invalid_AudiencesWithSlashValidAudienceSameLengthNotMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudienceWithSlash_IgnoreTrailingSlashFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1 + "/"],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1Slash)),
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
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = audiences1WithSlash,
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1Slash)),
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
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "A"],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "A")),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudienceWithDoubleSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "//"],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "//")),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "Invalid_ValidAudiencesWithDoubleSlash_IgnoreTrailingSlashTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithTwoSlashes,
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1 + "//")),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Invalid_TokenAudienceWithSlash_IgnoreTrailingSlashFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
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
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "Invalid_TokenAudiencesWithSlash_IgnoreTrailingSlashFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
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
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences2,
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(commaAudience2)),
                            null)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithTwoSlashes,
                        TestId = "TokenAudienceWithTwoSlashesVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new TokenValidationError(
                            ValidationErrorType.SecurityTokenInvalidAudience,
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1 + "//"),
                                LogHelper.MarkAsNonPII(audience1)),
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

            internal Result<string, ITokenValidationError> Result { get; set; }
        }


    }
}
