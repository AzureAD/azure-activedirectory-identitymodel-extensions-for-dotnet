// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public partial class ExtensibilityTesting
    {
        public static TheoryData<SignatureExtensibilityTheoryData> GenerateSignatureExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<SignatureExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomSignatureValidationError
            // Test cases where delegate is overridden and return a CustomSignatureValidationError
            // CustomSignatureValidationError : SignatureValidationError, ExceptionType: SecurityTokenInvalidSignatureException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "CustomSignatureValidatorDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.CustomSignatureValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorDelegate)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0))
            });

            // CustomSignatureValidationError : SignatureValidationError, ExceptionType: CustomSecurityTokenInvalidSignatureException : SecurityTokenInvalidSignatureException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "CustomSignatureValidatorCustomExceptionDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionDelegate)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0)),
            });

            // CustomSignatureValidationError : SignatureValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "CustomSignatureValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.CustomSignatureValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomSignatureValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0)),
            });

            // CustomSignatureValidationError : SignatureValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomSignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.CustomSignatureValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomSignatureValidationError.CustomSignatureValidationFailureType,
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0)),
            });
            #endregion

            #region return SignatureValidationError
            // Test cases where delegate is overridden and return an SignatureValidationError
            // SignatureValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidSignatureException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "SignatureValidatorDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.SignatureValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    nameof(CustomSignatureValidationDelegates.SignatureValidatorDelegate)),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.SignatureValidatorDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0))
            });

            // SignatureValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidSignatureException : SecurityTokenInvalidSignatureException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "SignatureValidatorCustomSignatureExceptionTypeDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.SignatureValidatorCustomSignatureExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // SignatureValidationError does not handle the exception type 'CustomSecurityTokenInvalidSignatureException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidSignatureException),
                        nameof(CustomSignatureValidationDelegates.SignatureValidatorCustomSignatureExceptionTypeDelegate))),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.SignatureValidatorCustomSignatureExceptionTypeDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(CustomSecurityTokenInvalidSignatureException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0))
            });

            // SignatureValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "SignatureValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                CustomSignatureValidationDelegates.SignatureValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // SignatureValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomSignatureValidationDelegates.SignatureValidatorCustomExceptionTypeDelegate))),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(
                        nameof(CustomSignatureValidationDelegates.SignatureValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomSignatureValidationDelegates.cs", 0))
            });

            // SignatureValidationError : ValidationError, ExceptionType: SecurityTokenInvalidSignatureException, inner: CustomSecurityTokenInvalidSignatureException
            theoryData.Add(new SignatureExtensibilityTheoryData(
                "SignatureValidatorThrows",
                tokenHandlerType,
                CustomSignatureValidationDelegates.SignatureValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    string.Format(Tokens.LogMessages.IDX10272),
                    typeof(CustomSecurityTokenInvalidSignatureException)),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10272), null),
                    ValidationFailureType.SignatureValidatorThrew,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame(stackFrameFileName, 0),
                    null, // no inner validation error
                    new SecurityTokenInvalidSignatureException(nameof(CustomSignatureValidationDelegates.SignatureValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
