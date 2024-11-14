// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;

using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml.Extensibility.Tests
{
    public partial class SamlSecurityTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(Audience_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_AudienceValidator_Extensibility(AudienceExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_AudienceValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.AudienceValidationError!.AddStackFrame(new StackFrame(false));

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.SamlSecurityTokenHandler.ValidateTokenAsync(
                    theoryData.SamlToken!,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    if (validatedToken.ValidatedAudience is not null)
                        IdentityComparer.AreStringsEqual(validatedToken.ValidatedAudience, theoryData.ValidatedAudience, context);
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.AudienceValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<AudienceExtensibilityTheoryData> Audience_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<AudienceExtensibilityTheoryData>();
                CallContext callContext = new CallContext();
                string audience = Default.Audience;
                List<string> tokenAudiences = [audience];

                #region return CustomAudienceValidationError
                // Test cases where delegate is overridden and return a CustomAudienceValidationError
                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.CustomAudienceValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("CustomValidationDelegates.cs", 160),
                        tokenAudiences,
                        null)
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorCustomExceptionDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomValidationDelegates.cs", 175),
                        tokenAudiences,
                        null),
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorUnknownExceptionDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.CustomAudienceValidatorUnknownExceptionDelegate,
                    extraStackFrames: 2)
                {
                    // CustomAudienceValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorUnknownExceptionDelegate))),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorUnknownExceptionDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(NotSupportedException),
                        new StackFrame("CustomValidationDelegates.cs", 205),
                        tokenAudiences,
                        null),
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate), null),
                        CustomAudienceValidationError.CustomAudienceValidationFailureType,
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomValidationDelegates.cs", 190),
                        tokenAudiences,
                        null),
                });
                #endregion

                #region return AudienceValidationError
                // Test cases where delegate is overridden and return an AudienceValidationError
                // AudienceValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.AudienceValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidatorDelegates.AudienceValidatorDelegate)),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.AudienceValidatorDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("CustomValidationDelegates.cs", 235),
                        tokenAudiences,
                        null)
                });

                // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorCustomAudienceExceptionTypeDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // AudienceValidationError does not handle the exception type 'CustomSecurityTokenInvalidAudienceException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidAudienceException),
                            nameof(CustomAudienceValidatorDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate))),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomValidationDelegates.cs", 259),
                        tokenAudiences,
                        null)
                });

                // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorCustomExceptionTypeDelegate",
                    audience,
                    CustomAudienceValidatorDelegates.AudienceValidatorCustomExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // AudienceValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomAudienceValidatorDelegates.AudienceValidatorCustomExceptionTypeDelegate))),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidatorDelegates.AudienceValidatorCustomExceptionTypeDelegate), null),
                        ValidationFailureType.AudienceValidationFailed,
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomValidationDelegates.cs", 274),
                        tokenAudiences,
                        null)
                });

                // AudienceValidationError : ValidationError, ExceptionType: SecurityTokenInvalidAudienceException, inner: CustomSecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorThrows",
                    audience,
                    CustomAudienceValidatorDelegates.AudienceValidatorThrows,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        string.Format(Tokens.LogMessages.IDX10270),
                        typeof(CustomSecurityTokenInvalidAudienceException)),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10270), null),
                        ValidationFailureType.AudienceValidatorThrew,
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("SamlSecurityTokenHandler.ValidateToken.Internal.cs", 250),
                        tokenAudiences,
                        null,
                        new SecurityTokenInvalidAudienceException(nameof(CustomAudienceValidatorDelegates.AudienceValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class AudienceExtensibilityTheoryData : TheoryDataBase
        {
            internal AudienceExtensibilityTheoryData(string testId, string audience, AudienceValidationDelegate audienceValidator, int extraStackFrames) : base(testId)
            {
                SamlToken = (SamlSecurityToken)SamlSecurityTokenHandler.CreateToken(new()
                {
                    Subject = Default.SamlClaimsIdentity,
                    Audience = audience,
                    Issuer = Default.Issuer,
                });
                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = audienceValidator,
                    IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation,
                    IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation,
                    LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation,
                    SignatureValidator = SkipValidationDelegates.SkipSignatureValidation,
                    TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation,
                    TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation
                };

                ExtraStackFrames = extraStackFrames;
            }

            public SamlSecurityToken SamlToken { get; }

            public SamlSecurityTokenHandler SamlSecurityTokenHandler { get; } = new SamlSecurityTokenHandler();

            public bool IsValid { get; set; }

            internal string? ValidatedAudience { get; set; }

            internal ValidationParameters? ValidationParameters { get; set; }

            internal AudienceValidationError? AudienceValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
