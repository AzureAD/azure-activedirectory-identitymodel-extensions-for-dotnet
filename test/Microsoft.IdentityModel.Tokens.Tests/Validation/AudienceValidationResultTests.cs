// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class AudienceValidationResultTests
    {
        [Theory, MemberData(nameof(ValidateAudienceParametersTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateAudienceParameters(AudienceValidationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.AudienceValidatorResultTests", theoryData);

            if (theoryData.AudiencesToAdd != null)
            {
                foreach (string audience in theoryData.AudiencesToAdd)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            AudienceValidationResult audienceValidationResult = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (audienceValidationResult.Exception == null)
                theoryData.ExpectedException.ProcessNoException();
            else
                theoryData.ExpectedException.ProcessException(audienceValidationResult.Exception, context);

            IdentityComparer.AreAudienceValidationResultsEqual(
                audienceValidationResult,
                theoryData.AudienceValidationResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AudienceValidationTheoryData> ValidateAudienceParametersTestCases
        {
            get
            {
                return new TheoryData<AudienceValidationTheoryData>
                {
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TestId = "ValidationParametersNull",
                        ValidationParameters = null,
                        AudienceValidationResult = new AudienceValidationResult(
                            "audience1",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("validationParameters")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = null,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10207:"),
                        TestId = "AudiencesNull",
                        AudienceValidationResult = new AudienceValidationResult(
                            "null",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10207,
                                    null),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string>{ },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10206:"),
                        TestId = "AudiencesEmptyList",
                        ValidationParameters = new ValidationParameters(),
                        AudienceValidationResult = new AudienceValidationResult(
                            "empty",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10206,
                                    null),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudiencesEmptyString",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [String.Empty],
                        AudienceValidationResult = new AudienceValidationResult(
                            "audience1",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII("audience1"),
                                    LogHelper.MarkAsNonPII(String.Empty)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = new List<string> { "audience1" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudiencesWhiteSpace",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = ["    "],
                        AudienceValidationResult = new AudienceValidationResult(
                            "audience1",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII("audience1"),
                                    LogHelper.MarkAsNonPII("    ")),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ValidateAudienceTheoryData))]
        public void ValidateAudience(AudienceValidationTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateAudience", theoryData);

            if (theoryData.AudiencesToAdd != null)
            {
                foreach (string audience in theoryData.AudiencesToAdd)
                    theoryData.ValidationParameters.ValidAudiences.Add(audience);
            }

            AudienceValidationResult audienceValidationResult = Validators.ValidateAudience(
                theoryData.Audiences,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext());

            if (audienceValidationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(audienceValidationResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException(context);

            IdentityComparer.AreAudienceValidationResultsEqual(
                audienceValidationResult,
                theoryData.AudienceValidationResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AudienceValidationTheoryData> ValidateAudienceTheoryData
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
                        Audiences = audiences1,
                        TestId = "SameLengthMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        AudienceValidationResult = new AudienceValidationResult(audience1)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "SameLengthNotMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(audience2)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "AudiencesValidAudienceWithSlashNotMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience2 + "/"],
                        SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, "Issuer"),
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(audience2Slash)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "AudiencesWithSlashValidAudienceSameLengthNotMatched",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience2Slash,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience2Slash),
                                    LogHelper.MarkAsNonPII(audience1)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudienceWithSlashVPFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1 + "/"],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(audience1Slash)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "ValidAudienceWithSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "/"],
                        AudienceValidationResult = new AudienceValidationResult(audience1)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudiencesWithSlashVPFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = audiences1WithSlash,
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(commaAudience1Slash)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        TestId = "ValidAudiencesWithSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithSlash,
                        AudienceValidationResult = new AudienceValidationResult(audience1)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudienceWithExtraChar",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "A"],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(audience1 + "A")),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudienceWithDoubleSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1 + "//"],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(audience1 + "//")),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "ValidAudiencesWithDoubleSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences1WithTwoSlashes,
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1),
                                    LogHelper.MarkAsNonPII(commaAudience1 + "//")),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "TokenAudienceWithSlashVPFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1Slash,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1Slash),
                                    LogHelper.MarkAsNonPII(audience1)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "TokenAudienceWithSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(audience1Slash)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences2WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "TokenAudienceWithSlashNotEqual",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience2Slash,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience2Slash),
                                    LogHelper.MarkAsNonPII(audience1)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "TokenAudiencesWithSlashVPFalse",
                        ValidationParameters = new ValidationParameters{ IgnoreTrailingSlashWhenValidatingAudience = false },
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1Slash,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1Slash),
                                    LogHelper.MarkAsNonPII(audience1)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        TestId = "TokenAudiencesWithSlashVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(audience1Slash)
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithSlash,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "TokenAudiencesWithSlashValidAudiencesNotMatchedVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = audiences2,
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1Slash,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1Slash),
                                    LogHelper.MarkAsNonPII(commaAudience2)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    },
                    new AudienceValidationTheoryData
                    {
                        Audiences = audiences1WithTwoSlashes,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                        TestId = "TokenAudienceWithTwoSlashesVPTrue",
                        ValidationParameters = new ValidationParameters(),
                        AudiencesToAdd = [audience1],
                        AudienceValidationResult = new AudienceValidationResult(
                            commaAudience1 + "//",
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX10215,
                                    LogHelper.MarkAsNonPII(commaAudience1 + "//"),
                                    LogHelper.MarkAsNonPII(audience1)),
                                ExceptionDetail.ExceptionType.SecurityTokenInvalidAudience,
                                new StackFrame(true),
                                null)),
                    }
                };
            }
        }

        public class AudienceValidationTheoryData : TheoryDataBase
        {
            public List<string> Audiences { get; set; }

            internal AudienceValidationResult AudienceValidationResult { get; set; }

            public SecurityToken SecurityToken { get; set; }

            internal ValidationParameters ValidationParameters { get; set; } = new ValidationParameters();

            internal ValidationFailureType ValidationFailureType { get; set; }
            public List<string> AudiencesToAdd { get; internal set; }
        }


    }
}
