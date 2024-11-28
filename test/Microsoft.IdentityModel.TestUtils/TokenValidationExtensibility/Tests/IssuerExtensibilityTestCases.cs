// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public partial class ExtensibilityTesting
    {
        public static TheoryData<IssuerExtensibilityTheoryData> GenerateIssuerExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<IssuerExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomIssuerValidationError
            // Test cases where delegate is overridden and return an CustomIssuerValidationError
            // CustomIssuerValidationError : IssuerValidationError, ExceptionType: SecurityTokenInvalidIssuerException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "CustomIssuerValidatorDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync,
                extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidIssuerException),
                    nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid)
            });

            // CustomIssuerValidationError : IssuerValidationError, ExceptionType: CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "CustomIssuerValidatorCustomExceptionDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync,
                extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid),
            });

            // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "CustomIssuerValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync,
                extraStackFrames)
            {
                // CustomIssuerValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync))),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorUnknownExceptionDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid),
            });

            // CustomIssuerValidationError : IssuerValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomIssuerValidationFailureType
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync,
                extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync)),
                ValidationError = new CustomIssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.CustomIssuerValidatorCustomExceptionCustomFailureTypeDelegateAsync), null),
                    CustomIssuerValidationError.CustomIssuerValidationFailureType,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid,
                    null),
            });
            #endregion

            #region return IssuerValidationError
            // Test cases where delegate is overridden and return an IssuerValidationError
            // IssuerValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidIssuerException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "IssuerValidatorDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync,
                extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidIssuerException),
                    nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync)),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(SecurityTokenInvalidIssuerException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid)
            });

            // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "IssuerValidatorCustomIssuerExceptionTypeDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync,
                extraStackFrames)
            {
                // IssuerValidationError does not handle the exception type 'CustomSecurityTokenInvalidIssuerException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidIssuerException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync))),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomIssuerExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenInvalidIssuerException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid)
            });

            // IssuerValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "IssuerValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync,
                extraStackFrames)
            {
                // IssuerValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync))),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerValidationDelegates.IssuerValidatorCustomExceptionTypeDelegateAsync), null),
                    ValidationFailureType.IssuerValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomIssuerValidationDelegates.cs", 0),
                    issuerGuid)
            });

            // IssuerValidationError : ValidationError, ExceptionType: SecurityTokenInvalidIssuerException, inner: CustomSecurityTokenInvalidIssuerException
            theoryData.Add(new IssuerExtensibilityTheoryData(
                "IssuerValidatorThrows",
                tokenHandlerType,
                issuerGuid,
                CustomIssuerValidationDelegates.IssuerValidatorThrows,
                extraStackFrames - 1) // when throwing an exception, the stack trace contains one less frame
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidIssuerException),
                    string.Format(Tokens.LogMessages.IDX10269),
                    typeof(CustomSecurityTokenInvalidIssuerException)),
                ValidationError = new IssuerValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10269), null),
                    ValidationFailureType.IssuerValidatorThrew,
                    typeof(SecurityTokenInvalidIssuerException),
                    new StackFrame(stackFrameFileName, 0),
                    issuerGuid,
                    new SecurityTokenInvalidIssuerException(nameof(CustomIssuerValidationDelegates.IssuerValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
