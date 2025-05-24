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
        public static TheoryData<TokenReplayExtensibilityTheoryData> GenerateTokenReplayExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<TokenReplayExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            DateTime expirationTime = DateTime.UtcNow + TimeSpan.FromHours(1);

            #region return CustomTokenReplayValidationError
            // Test cases where delegate is overridden and return a CustomTokenReplayValidationError
            // CustomTokenReplayValidationError : TokenReplayValidationError, ExceptionType: SecurityTokenReplayDetectedException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "CustomTokenReplayValidationDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.CustomTokenReplayValidationDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenReplayDetectedException),
                    nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidationDelegate)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidationDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(SecurityTokenReplayDetectedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime)
            });

            // CustomTokenReplayValidationError : TokenReplayValidationError, ExceptionType: CustomSecurityTokenReplayDetectedException : SecurityTokenReplayDetectedException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "CustomTokenReplayValidatorCustomExceptionDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenReplayDetectedException),
                    nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionDelegate)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(CustomSecurityTokenReplayDetectedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime),
            });

            // CustomTokenReplayValidationError : TokenReplayValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "CustomTokenReplayValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomTokenReplayValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime),
            });

            // CustomTokenReplayValidationError : TokenReplayValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenReplayDetectedException),
                    nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomTokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.CustomTokenReplayValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomTokenReplayValidationError.CustomTokenReplayValidationFailureType,
                    typeof(CustomSecurityTokenReplayDetectedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime),
            });
            #endregion

            #region return TokenReplayValidationError
            // Test cases where delegate is overridden and return an TokenReplayValidationError
            // TokenReplayValidationError : ValidationError, ExceptionType:  SecurityTokenReplayDetectedException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "TokenReplayValidationDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.TokenReplayValidationDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenReplayDetectedException),
                    nameof(CustomTokenReplayValidationDelegates.TokenReplayValidationDelegate)),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.TokenReplayValidationDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(SecurityTokenReplayDetectedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime)
            });

            // TokenReplayValidationError : ValidationError, ExceptionType:  CustomSecurityTokenReplayDetectedException : SecurityTokenReplayDetectedException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // TokenReplayValidationError does not handle the exception type 'CustomSecurityTokenReplayDetectedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenReplayDetectedException),
                        nameof(CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate))),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomTokenReplayDetectedExceptionTypeDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(CustomSecurityTokenReplayDetectedException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime)
            });

            // TokenReplayValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "TokenReplayValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // TokenReplayValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomExceptionTypeDelegate))),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(
                        nameof(CustomTokenReplayValidationDelegates.TokenReplayValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.TokenReplayValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomTokenReplayValidationDelegates.cs", 0),
                    expirationTime)
            });

            // TokenReplayValidationError : ValidationError, ExceptionType: SecurityTokenReplayDetectedException, inner: CustomSecurityTokenReplayDetectedException
            theoryData.Add(new TokenReplayExtensibilityTheoryData(
                "TokenReplayValidatorThrows",
                tokenHandlerType,
                expirationTime,
                CustomTokenReplayValidationDelegates.TokenReplayValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenReplayDetectedException),
                    string.Format(Tokens.LogMessages.IDX10276),
                    typeof(CustomSecurityTokenReplayDetectedException)),
                ValidationError = new TokenReplayValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10276), null),
                    ValidationFailureType.TokenReplayValidatorThrew,
                    typeof(SecurityTokenReplayDetectedException),
                    new StackFrame(stackFrameFileName, 0),
                    expirationTime,
                    new SecurityTokenReplayDetectedException(nameof(CustomTokenReplayValidationDelegates.TokenReplayValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
