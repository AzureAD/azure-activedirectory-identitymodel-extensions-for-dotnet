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
        public static TheoryData<AlgorithmExtensibilityTheoryData> GenerateAlgorithmExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            TheoryData<AlgorithmExtensibilityTheoryData> theoryData = new();
            CallContext callContext = new CallContext();

            #region return CustomAlgorithmValidationError
            // Test cases where delegate is overridden and return a CustomAlgorithmValidationError
            // CustomAlgorithmValidationError : AlgorithmValidationError, ExceptionType: SecurityTokenInvalidAlgorithmException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "CustomAlgorithmValidatorDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(SecurityTokenInvalidAlgorithmException)),
                ExpectedInnerException = new ExpectedException(
                    typeof(SecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorDelegate)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(SecurityTokenInvalidAlgorithmException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm")
            });

            // CustomAlgorithmValidationError : AlgorithmValidationError, ExceptionType: CustomSecurityTokenInvalidAlgorithmException : SecurityTokenInvalidAlgorithmException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "CustomAlgorithmValidatorCustomExceptionDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(CustomSecurityTokenInvalidAlgorithmException)),
                ExpectedInnerException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionDelegate)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm"),
            });

            // CustomAlgorithmValidationError : AlgorithmValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "CustomAlgorithmValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomAlgorithmValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(SecurityTokenException)),
                ExpectedInnerException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm"),
            });

            // CustomAlgorithmValidationError : AlgorithmValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(CustomSecurityTokenInvalidAlgorithmException)),
                ExpectedInnerException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomAlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.CustomAlgorithmValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomAlgorithmValidationError.CustomAlgorithmValidationFailureType,
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm"),
            });
            #endregion

            #region return AlgorithmValidationError
            // Test cases where delegate is overridden and return an AlgorithmValidationError
            // AlgorithmValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidAlgorithmException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "AlgorithmValidatorDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.AlgorithmValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(SecurityTokenInvalidAlgorithmException)),
                ExpectedInnerException = new ExpectedException(
                    typeof(SecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorDelegate)),
                ValidationError = new AlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(SecurityTokenInvalidAlgorithmException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm")
            });

            // AlgorithmValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidAlgorithmException : SecurityTokenInvalidAlgorithmException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // AlgorithmValidationError does not handle the exception type 'CustomSecurityTokenInvalidAlgorithmException'
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(SecurityTokenException)),
                ExpectedInnerException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidAlgorithmException),
                        nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate))),
                ValidationError = new AlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomAlgorithmExceptionTypeDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm")
            });

            // AlgorithmValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "AlgorithmValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // AlgorithmValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10518:",
                    typeof(SecurityTokenException)),
                ExpectedInnerException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomExceptionTypeDelegate))),
                ValidationError = new AlgorithmValidationError(
                    new MessageDetail(
                        nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.AlgorithmValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomAlgorithmValidationDelegates.cs", 0),
                    "algorithm")
            });

            // SignatureValidationError : ValidationError, ExceptionType: SecurityTokenInvalidSignatureException, inner: CustomSecurityTokenInvalidAlgorithmException
            theoryData.Add(new AlgorithmExtensibilityTheoryData(
                "AlgorithmValidatorThrows",
                tokenHandlerType,
                CustomAlgorithmValidationDelegates.AlgorithmValidatorThrows,
                extraStackFrames: extraStackFrames + 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidSignatureException),
                    "IDX10273:",
                    typeof(CustomSecurityTokenInvalidAlgorithmException)),
                ExpectedInnerException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAlgorithmException),
                    nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorThrows)),
                ValidationError = new SignatureValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10273), null),
                    ValidationFailureType.AlgorithmValidatorThrew,
                    typeof(SecurityTokenInvalidSignatureException),
                    new StackFrame(stackFrameFileName, 0),
                    null, // no inner validation error
                    new CustomSecurityTokenInvalidAlgorithmException(nameof(CustomAlgorithmValidationDelegates.AlgorithmValidatorThrows), null)
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
