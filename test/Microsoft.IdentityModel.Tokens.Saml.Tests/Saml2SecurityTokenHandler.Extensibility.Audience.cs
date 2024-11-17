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
namespace Microsoft.IdentityModel.Tokens.Saml2.Extensibility.Tests
{
    public partial class Saml2SecurityTokenHandlerValidateTokenAsyncTests
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
                ValidationResult<ValidatedToken> validationResult = await theoryData.Saml2SecurityTokenHandler.ValidateTokenAsync(
                    theoryData.Saml2Token!,
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
                    CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate), null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 160),
                        tokenAudiences,
                        null, // validAudiences
                        ValidationFailureType.AudienceValidationFailed)
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorCustomExceptionDelegate",
                    audience,
                    CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate), null),
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 175),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidationFailed),
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorUnknownExceptionDelegate",
                    audience,
                    CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate,
                    extraStackFrames: 2)
                {
                    // CustomAudienceValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate))),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate), null),
                        typeof(NotSupportedException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 205),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidationFailed),
                });

                // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate",
                    audience,
                    CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate)),
                    AudienceValidationError = new CustomAudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 190),
                        tokenAudiences,
                        null,
                        CustomAudienceValidationError.CustomAudienceValidationFailureType),
                });
                #endregion

                #region return AudienceValidationError
                // Test cases where delegate is overridden and return an AudienceValidationError
                // AudienceValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorDelegate",
                    audience,
                    CustomAudienceValidationDelegates.AudienceValidatorDelegate,
                    extraStackFrames: 2)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorDelegate)),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.AudienceValidatorDelegate), null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 235),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidationFailed)
                });

                // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorCustomAudienceExceptionTypeDelegate",
                    audience,
                    CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // AudienceValidationError does not handle the exception type 'CustomSecurityTokenInvalidAudienceException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidAudienceException),
                            nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate))),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 259),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidationFailed)
                });

                // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorCustomExceptionTypeDelegate",
                    audience,
                    CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate,
                    extraStackFrames: 2)
                {
                    // AudienceValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate))),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate), null),
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomAudienceValidationDelegates.cs", 274),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidationFailed)
                });

                // AudienceValidationError : ValidationError, ExceptionType: SecurityTokenInvalidAudienceException, inner: CustomSecurityTokenInvalidAudienceException
                theoryData.Add(new AudienceExtensibilityTheoryData(
                    "AudienceValidatorThrows",
                    audience,
                    CustomAudienceValidationDelegates.AudienceValidatorThrows,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidAudienceException),
                        string.Format(Tokens.LogMessages.IDX10270),
                        typeof(CustomSecurityTokenInvalidAudienceException)),
                    AudienceValidationError = new AudienceValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10270), null),
                        typeof(SecurityTokenInvalidAudienceException),
                        new StackFrame("Saml2SecurityTokenHandler.ValidateToken.Internal.cs", 250),
                        tokenAudiences,
                        null,
                        ValidationFailureType.AudienceValidatorThrew,
                        new SecurityTokenInvalidAudienceException(nameof(CustomAudienceValidationDelegates.AudienceValidatorThrows))
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
                Saml2Token = (Saml2SecurityToken)Saml2SecurityTokenHandler.CreateToken(new()
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

            public Saml2SecurityToken Saml2Token { get; }

            public Saml2SecurityTokenHandler Saml2SecurityTokenHandler { get; } = new Saml2SecurityTokenHandler();

            public bool IsValid { get; set; }

            internal string? ValidatedAudience { get; set; }

            internal ValidationParameters? ValidationParameters { get; set; }

            internal AudienceValidationError? AudienceValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
