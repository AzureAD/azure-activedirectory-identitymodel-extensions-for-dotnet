// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    [CollectionDefinition("AudienceValidationTests", DisableParallelization = true)]
    public class AudienceValidationTests
    {
        [Theory, MemberData(nameof(InvalidParameterTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidAudienceParameters(ValidateAudienceTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidAudienceParameters", theoryData);
            AppContext.SetSwitch(AppContextSwitches.DoNotScrubExceptionsSwitch, theoryData.DoNotScrubErrorMessages);

            try
            {
                if (theoryData.ValidAudiences != null)
                {
                    foreach (string audience in theoryData.ValidAudiences)
                        theoryData.ValidationParameters.ValidAudiences.Add(audience);
                }

                ValidationResult<string, ValidationError> validationResult =
                    Validators.ValidateAudience(
                        theoryData.TokenAudiences,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                    context.Diffs.Add($"Expected validation to fail, but it succeeded. TestId {theoryData.TestId}.");
                else
                {
                    ValidationError validationError = validationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.ValidationResult.Error.FailureType.Name,
                        context);

                    IdentityComparer.AreStringsEqual(
                        validationError.MessageDetail.Message,
                        theoryData.ValidationResult.Error.MessageDetail.Message,
                        context);

                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateAudienceTheoryData> InvalidParameterTestCases
        {
            get
            {
                return new TheoryData<ValidateAudienceTheoryData>
                {
                    new ValidateAudienceTheoryData("ValidationParametersNull")
                    {
                        TokenAudiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationParameters = null,
                        ValidationResult = new AudienceValidationError(
                            MessageDetail.NullParameter("validationParameters"),
                            ValidationFailureType.NullArgument,
                            null,
                            null,
                            null)
                    },
                    new ValidateAudienceTheoryData("AudiencesNull")
                    {
                        TokenAudiences = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidationResult = new AudienceValidationError(
                            MessageDetail.NullParameter("tokenAudiences"),
                            ValidationFailureType.NullArgument,
                            null,
                            null,
                            null)
                    },
                    new ValidateAudienceTheoryData("AudiencesEmptyList")
                    {
                        TokenAudiences = new List<string> { },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10206,
                                null),
                            AudienceValidationFailure.NoAudienceInToken,
                            null,
                            null,
                            null)
                    },
                    new ValidateAudienceTheoryData("AudiencesEmptyString_ScrubbedMessage")
                    {
                        TokenAudiences = new List<string> { string.Empty },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215S),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            null,
                            null)
                    },
                    new ValidateAudienceTheoryData("AudiencesWhiteSpace_ScrubbedMessage")
                    {
                        TokenAudiences = new List<string> { "    " },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215S),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            null,
                            null)
                    },

                    new ValidateAudienceTheoryData("AudiencesEmptyString")
                    {
                        TokenAudiences = new List<string> { string.Empty },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(string.Empty),
                                LogHelper.MarkAsNonPII("audience1")),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            null,
                            null),
                        DoNotScrubErrorMessages = true
                    },
                    new ValidateAudienceTheoryData("AudiencesWhiteSpace")
                    {
                        TokenAudiences = new List<string> { "    " },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = ["audience1"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII("    "),
                                LogHelper.MarkAsNonPII("audience1")),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            null,
                            null),
                        DoNotScrubErrorMessages = true
                    },
                };
            }
        }

        [Theory, MemberData(nameof(InValidTestCases), DisableDiscoveryEnumeration = true)]
        public void InvalidAudiences(ValidateAudienceTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.InvalidAudiences", theoryData);

            if (theoryData.ValidAudiences != null)
            {
                foreach (string audience in theoryData.ValidAudiences)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            try
            {
                ValidationResult<string, ValidationError> validationResult =
                    Validators.ValidateAudience(
                        theoryData.TokenAudiences,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    context.Diffs.Add($"Expected validation to fail, but it succeeded. TestId {theoryData.TestId}.");
                }
                else
                {
                    ValidationError validationError = validationResult.Error;
                    IdentityComparer.AreStringsEqual(
                        validationError.FailureType.Name,
                        theoryData.ValidationResult.Error.FailureType.Name,
                        context);

                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateAudienceTheoryData> InValidTestCases
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

                return new TheoryData<ValidateAudienceTheoryData>
                {
                    new ValidateAudienceTheoryData("SameLengthNotMatched")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience2],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            [audience2])
                    },
                    new ValidateAudienceTheoryData("AudiencesValidAudienceWithSlashNotMatched")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience2 + "/"],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience2Slash)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            [audience2 + "/"])
                    },
                    new ValidateAudienceTheoryData("AudiencesWithSlashValidAudienceSameLengthNotMatched")
                    {
                        TokenAudiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1WithSlash,
                            [audience1])
                    },
                    new ValidateAudienceTheoryData("ValidAudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1 + "/"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1Slash)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            [audience1 + "/"])
                    },
                    new ValidateAudienceTheoryData("ValidAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = audiences1WithSlash,
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1Slash)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            audiences1WithSlash)
                    },
                    new ValidateAudienceTheoryData("ValidAudienceWithExtraChar")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "A"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "A")),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            [audience1 + "A"])
                    },
                    new ValidateAudienceTheoryData("AudienceWithDoubleSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "//"],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(audience1 + "//")),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            [audience1 + "//"])
                    },
                    new ValidateAudienceTheoryData("AudiencesWithDoubleSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences1WithTwoSlashes,
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1),
                                LogHelper.MarkAsNonPII(commaAudience1 + "//")),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1,
                            audiences1WithTwoSlashes)
                    },
                    new ValidateAudienceTheoryData("TokenAudienceWithSlash_IgnoreTrailingSlashFalse")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1WithSlash,
                            [audience1])
                    },
                    new ValidateAudienceTheoryData("TokenAudienceWithSlashNotEqual")
                    {
                        TokenAudiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience2Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences2WithSlash,
                            [audience1])
                    },
                    new ValidateAudienceTheoryData("TokenAudiencesWithSlash_IgnoreTrailingSlashFalse")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        ValidAudiences = [audience1],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(audience1)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1WithSlash,
                            [audience1])
                    },
                    new ValidateAudienceTheoryData("TokenAudiencesWithSlashValidAudiencesNotMatched_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences2,
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1Slash),
                                LogHelper.MarkAsNonPII(commaAudience2)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1WithSlash,
                            audiences2)
                    },
                    new ValidateAudienceTheoryData("TokenAudienceWithTwoSlashesVPTrue")
                    {
                        TokenAudiences = audiences1WithTwoSlashes,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        ValidationResult = new AudienceValidationError(
                            new MessageDetail(
                                LogMessages.IDX10215,
                                LogHelper.MarkAsNonPII(commaAudience1 + "//"),
                                LogHelper.MarkAsNonPII(audience1)),
                            AudienceValidationFailure.DidNotMatch,
                            null,
                            audiences1WithTwoSlashes,
                            [audience1])
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ValidTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidAudiences(ValidateAudienceTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidAudiences", theoryData);

            if (theoryData.ValidAudiences != null)
            {
                foreach (string audience in theoryData.ValidAudiences)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            try
            {
                ValidationResult<string, ValidationError> validationResult =
                    Validators.ValidateAudience(
                        theoryData.TokenAudiences,
                        theoryData.SecurityToken,
                        theoryData.ValidationParameters,
                        theoryData.CallContext);

                if (validationResult.Succeeded)
                {
                    IdentityComparer.AreStringsEqual(
                        validationResult.Result,
                        theoryData.ValidationResult.Result,
                        context);
                }
                else
                {
                    context.Diffs.Add($"Expected validation to succeed, but it failed with: {validationResult.Error}.");
                }
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateAudienceTheoryData> ValidTestCases
        {
            get
            {
                var audience1 = "http://audience1.com";
                var audience1Slash = audience1 + "/";
                List<string> audiences1 = new List<string> { "", audience1 };
                List<string> audiences1WithSlash = new List<string> { "", audience1 + "/" };

                return new TheoryData<ValidateAudienceTheoryData>
                {
                    new ValidateAudienceTheoryData("SameLengthMatched")
                    {
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        ValidationResult = audience1
                    },
                    new ValidateAudienceTheoryData("AudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1 + "/"],
                        ValidationResult = audience1
                    },
                    new ValidateAudienceTheoryData("AudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = audiences1WithSlash,
                        ValidationResult = audience1
                    },
                    new ValidateAudienceTheoryData("TokenAudienceWithSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        ValidationResult = audience1Slash
                    },
                    new ValidateAudienceTheoryData("TokenAudiencesWithSlash_IgnoreTrailingSlashTrue")
                    {
                        TokenAudiences = audiences1WithSlash,
                        ValidationParameters = new ValidationParameters(),
                        ValidAudiences = [audience1],
                        ValidationResult = audience1Slash
                    }
                };
            }
        }

    }
}
