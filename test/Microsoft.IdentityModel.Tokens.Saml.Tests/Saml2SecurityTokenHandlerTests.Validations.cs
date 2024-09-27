// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Logging;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml2.Tests
{
    public partial class Saml2SecurityTokenHandlerTests
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

            ValidationResult<string> result = Saml2SecurityTokenHandler.ValidateAudience(
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
