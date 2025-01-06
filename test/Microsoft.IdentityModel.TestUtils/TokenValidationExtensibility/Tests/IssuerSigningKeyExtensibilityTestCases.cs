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
        public static TheoryData<IssuerSigningKeyExtensibilityTheoryData> GenerateIssuerSigningKeyExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<IssuerSigningKeyExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();

            #region return CustomIssuerSigningKeyValidationError
            // Test cases where delegate is overridden and return a CustomIssuerSigningKeyValidationError
            // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "CustomIssuerSigningKeyValidatorDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSigningKeyException),
                    nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(SecurityTokenInvalidSigningKeyException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: CustomSecurityTokenInvalidIssuerSigningKeyException : SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "CustomIssuerSigningKeyValidatorCustomExceptionDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "CustomIssuerSigningKeyValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomIssuerSigningKeyValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // CustomIssuerSigningKeyValidationError : IssuerSigningKeyValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomIssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.CustomIssuerSigningKeyValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomIssuerSigningKeyValidationError.CustomIssuerSigningKeyValidationFailureType,
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null),
            });
            #endregion

            #region return IssuerSigningKeyValidationError
            // Test cases where delegate is overridden and return an IssuerSigningKeyValidationError
            // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "IssuerSigningKeyValidatorDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSigningKeyException),
                    nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate)),
                ValidationError = new IssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(SecurityTokenInvalidSigningKeyException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidIssuerSigningKeyException : SecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // IssuerSigningKeyValidationError does not handle the exception type 'CustomSecurityTokenInvalidIssuerSigningKeyException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidSigningKeyException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate))),
                ValidationError = new IssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomIssuerSigningKeyExceptionTypeDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(CustomSecurityTokenInvalidSigningKeyException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // IssuerSigningKeyValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "IssuerSigningKeyValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // IssuerSigningKeyValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate))),
                ValidationError = new IssuerSigningKeyValidationError(
                    new MessageDetail(
                        nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.SigningKeyValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomIssuerSigningKeyValidationDelegates.cs", 0),
                    null)
            });

            // IssuerSigningKeyValidationError : ValidationError, ExceptionType: SecurityTokenInvalidIssuerSigningKeyException, inner: CustomSecurityTokenInvalidIssuerSigningKeyException
            theoryData.Add(new IssuerSigningKeyExtensibilityTheoryData(
                "IssuerSigningKeyValidatorThrows",
                tokenHandlerType,
                CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSigningKeyException),
                    string.Format(Tokens.LogMessages.IDX10274),
                    typeof(CustomSecurityTokenInvalidSigningKeyException)),
                ValidationError = new IssuerSigningKeyValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10274), null),
                    ValidationFailureType.IssuerSigningKeyValidatorThrew,
                    typeof(SecurityTokenInvalidSigningKeyException),
                    new StackFrame(stackFrameFileName, 0),
                    null,
                    new SecurityTokenInvalidSigningKeyException(nameof(CustomIssuerSigningKeyValidationDelegates.IssuerSigningKeyValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
