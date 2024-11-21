// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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
        [Theory, MemberData(nameof(Issuer_ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerValidator_Extensibility(IssuerExtensibilityTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.{nameof(ValidateTokenAsync_IssuerValidator_Extensibility)}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.IssuerValidationError!.AddStackFrame(new StackFrame(false));

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
                    if (validatedToken.ValidatedIssuer.HasValue)
                        IdentityComparer.AreValidatedIssuersEqual(validatedToken.ValidatedIssuer.Value, theoryData.ValidatedIssuer, context);
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.IssuerValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<IssuerExtensibilityTheoryData> Issuer_ExtensibilityTestCases
        {
            get
            {
                var theoryData = new TheoryData<IssuerExtensibilityTheoryData>();
                CallContext callContext = new CallContext();
                string issuerGuid = Guid.NewGuid().ToString();

                #region return CustomIssuerValidationError
                // Test cases where delegate is overridden and return an CustomIssuerValidationError
                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 88),
                        issuerGuid)
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorCustomExceptionDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 107),
                        issuerGuid),
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorUnknownExceptionDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync,
                    extraStackFrames: 1)
                {
                    // CustomIssuerValidationError does not handle the exception type 'NotSupportedException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(NotSupportedException),
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync))),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(NotSupportedException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 139),
                        issuerGuid),
                });

                // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomIssuerValidationFailureType
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync)),
                    IssuerValidationError = new CustomIssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync), null),
                        CustomIssuerValidationError.CustomIssuerValidationFailureType,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 123),
                        issuerGuid),
                });
                #endregion

                #region return IssuerValidationError
                // Test cases where delegate is overridden and return an IssuerValidationError
                // IssuerValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync,
                    extraStackFrames: 1)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 169),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorCustomIssuerExceptionTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync,
                    extraStackFrames: 1)
                {
                    // IssuerValidationError does not handle the exception type 'CustomSecurityTokenInvalidIssuerException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenInvalidIssuerException),
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync))),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 196),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorCustomExceptionTypeDelegate",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync,
                    extraStackFrames: 1)
                {
                    // IssuerValidationError does not handle the exception type 'CustomSecurityTokenException'
                    ExpectedException = ExpectedException.SecurityTokenException(
                        LogHelper.FormatInvariant(
                            Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                            typeof(CustomSecurityTokenException),
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync))),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync), null),
                        ValidationFailureType.IssuerValidationFailed,
                        typeof(CustomSecurityTokenException),
                        new StackFrame("CustomIssuerValidationDelegates.cs", 210),
                        issuerGuid)
                });

                // IssuerValidationError : ValidationError, ExceptionType: SecurityTokenInvalidIssuerException, inner: CustomSecurityTokenInvalidIssuerException
                theoryData.Add(new IssuerExtensibilityTheoryData(
                    "IssuerValidatorThrows",
                    issuerGuid,
                    CustomIssuerValidationDelegates.IssuerValidatorThrows,
                    extraStackFrames: 0)
                {
                    ExpectedException = new ExpectedException(
                        typeof(SecurityTokenInvalidIssuerException),
                        string.Format(Tokens.LogMessages.IDX10269),
                        typeof(CustomSecurityTokenInvalidIssuerException)),
                    IssuerValidationError = new IssuerValidationError(
                        new MessageDetail(
                            string.Format(Tokens.LogMessages.IDX10269), null),
                        ValidationFailureType.IssuerValidatorThrew,
                        typeof(SecurityTokenInvalidIssuerException),
                        new StackFrame("SamlSecurityTokenHandler.ValidateToken.Internal.cs", 92),
                        issuerGuid,
                        new SecurityTokenInvalidIssuerException(nameof(CustomIssuerValidationDelegates.IssuerValidatorThrows))
                    )
                });
                #endregion

                return theoryData;
            }
        }

        public class IssuerExtensibilityTheoryData : TheoryDataBase
        {
            internal IssuerExtensibilityTheoryData(string testId, string issuer, IssuerValidationDelegateAsync issuerValidator, int extraStackFrames) : base(testId)
            {
                SamlToken = (SamlSecurityToken)SamlSecurityTokenHandler.CreateToken(new()
                {
                    Subject = Default.SamlClaimsIdentity,
                    Issuer = issuer,
                });

                ValidationParameters = new ValidationParameters
                {
                    AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation,
                    AudienceValidator = SkipValidationDelegates.SkipAudienceValidation,
                    IssuerValidatorAsync = issuerValidator,
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

            internal ValidatedIssuer ValidatedIssuer { get; set; }

            internal ValidationParameters? ValidationParameters { get; set; }

            internal IssuerValidationError? IssuerValidationError { get; set; }

            internal int ExtraStackFrames { get; }
        }
    }
}
#nullable restore
