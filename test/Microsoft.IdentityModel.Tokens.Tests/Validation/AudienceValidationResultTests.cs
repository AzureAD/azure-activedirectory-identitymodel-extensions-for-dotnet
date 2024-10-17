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

            if (theoryData.ValidAudiences != null)
            {
                foreach (string audience in theoryData.ValidAudiences)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            ValidationResult<string> result = Validators.ValidateAudience(
                theoryData.TokenAudiences,
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

                IdentityComparer.AreStringsEqual(
                    validationError.MessageDetail.Message,
                    theoryData.Result.UnwrapError().MessageDetail.Message,
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
                        TokenAudiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        ValidationParameters = null,
                        Result = new ValidationError(
                            MessageDetail.NullParameter("validationParameters"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesNull")
                    {
                        TokenAudiences = null,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            MessageDetail.NullParameter("tokenAudiences"),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesEmptyList")
                    {
                        TokenAudiences = new List<string> { },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                        ValidationParameters = new ValidationParameters(),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10206,
                                null),
                            ValidationFailureType.NoTokenAudiencesProvided,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesEmptyString")
                    {
                        TokenAudiences = new List<string> { string.Empty },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(string.Empty),
                                LogHelper.MarkAsNonPII("audience1")),
                            ValidationFailureType.AudienceValidationFailed,
                            typeof(SecurityTokenInvalidAudienceException),
                            null)
                    },
                    new AudienceValidationTheoryData("AudiencesWhiteSpace")
                    {
                        TokenAudiences = new List<string> { "    " },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("    "),
                                LogHelper.MarkAsNonPII("audience1")),
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

            if (theoryData.ValidAudiences != null)
            {
                foreach (string audience in theoryData.ValidAudiences)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            ValidationResult<string> result = Validators.ValidateAudience(
                theoryData.TokenAudiences,
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
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_SameLengthNotMatched")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience2],
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
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience2 + "/"],
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
                        TokenAudiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
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
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1 + "/"],
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
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "/"],
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = audiences1WithSlash,
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
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences1WithSlash,
                        Result = audience1
                    },
                    new AudienceValidationTheoryData("Invalid_ValidAudienceWithExtraChar")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "A"],
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
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "//"],
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
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences1WithTwoSlashes,
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
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1],
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
                        TokenAudiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudienceWithSlashNotEqual")
                    {
                        TokenAudiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
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
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1],
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
                        TokenAudiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        Result = audience1Slash
                    },
                    new AudienceValidationTheoryData("Invalid_TokenAudiencesWithSlashValidAudiencesNotMatched_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences2,
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
                        TokenAudiences = audiences1WithTwoSlashes,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
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

            public List<string> TokenAudiences { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; } = new ValidationParameters();

            internal ValidationFailureType ValidationFailureType { get; set; }

            public List<string> ValidAudiences { get; set; }

            internal ValidationResult<string> Result { get; set; }
        }
    }
}
