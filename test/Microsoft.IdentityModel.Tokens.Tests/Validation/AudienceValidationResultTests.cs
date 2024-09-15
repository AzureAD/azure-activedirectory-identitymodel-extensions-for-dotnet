// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AudienceValidationResultTests
    {
        [Theory, MemberData(nameof(ValidateAudienceParameterTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateAudienceParameters(AudienceValidationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateAudienceParameters", theoryData);

            if (theoryData.AudiencesToAdd != null)
            {
                foreach (string audience in theoryData.AudiencesToAdd)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            ValidationResult<string> result = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                theoryData.CallContext);

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

        public static TheoryData<AudienceValidationTheoryData> ValidateAudienceParameterTestCases
        {
            get
            {
                return new TheoryData<AudienceValidationTheoryData>
                {
                    new AudienceValidationTheoryData("ValidationParametersNull")
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        ValidationParameters = null,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("validationParameters")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesNull")
                    {
                        Audiences = null,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10207:"),
                        Result = new ValidationError(
                            new MessageDetail(LogMessages.IDX10207),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesEmptyList")
                    {
                        Audiences = new List<string> { },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10206,
                                null),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesEmptyString")
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [string.Empty],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII(string.Empty)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesWhiteSpace")
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = ["    "],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("audience1"),
                                LogHelper.MarkAsNonPII("    ")),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },

                };
            }
        }

        [Theory, MemberData(nameof(ValidateAudienceTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateAudienceTests(AudienceValidationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateAudienceTests", theoryData);

            if (theoryData.AudiencesToAdd != null)
            {
                foreach (string audience in theoryData.AudiencesToAdd)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            ValidationResult<string> result = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                theoryData.CallContext);

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
                    new AudienceValidationTheoryData("Valid_SameLengthMatched")
                    {
                        Audiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_SameLengthNotMatched")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_AudiencesValidAudienceWithSlashNotMatched")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2 + "/"],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2Slash)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_AudiencesWithSlashValidAudienceSameLengthNotMatched")
                    {
                        Audiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1 + "/"],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1Slash)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Valid_ValidAudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "/"],
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = audiences1WithSlash,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1Slash)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Valid_ValidAudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithSlash,
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudienceWithExtraChar")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "A"],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "A")),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudienceWithDoubleSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "//"],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "//")),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudiencesWithDoubleSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithTwoSlashes,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1 + "//")),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Valid_TokenAudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudienceWithSlashNotEqual")
                    {
                        Audiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("Valid_TokenAudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudiencesWithSlashValidAudiencesNotMatched_IgnoreTrailingSlashTrue")
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences2,
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(commaAudience2)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("TokenAudienceWithTwoSlashesVPTrue")
                    {
                        Audiences = audiences1WithTwoSlashes,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1 + "//"),
                                LogHelper.MarkAsNonPII(audience1)),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    }
                };
            }
        }

        public class AudienceValidationTheoryData : TheoryDataBase
        {
            public AudienceValidationTheoryData(string testId) : base(testId) { }

            public List<string> Audiences { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; } = new ValidationParameters();

            internal ValidationFailureType ValidationFailureType { get; set; }

            public List<string> AudiencesToAdd { get; set; }

            internal ValidationResult<string> Result { get; set; }
        }
    }
}
