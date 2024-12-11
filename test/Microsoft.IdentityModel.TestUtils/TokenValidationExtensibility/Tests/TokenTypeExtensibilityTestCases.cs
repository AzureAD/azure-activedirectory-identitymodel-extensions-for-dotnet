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
        public static TheoryData<TokenTypeExtensibilityTheoryData> GenerateTokenTypeExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<TokenTypeExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string tokenType = "NOTJWT";

            #region return CustomTokenTypeValidationError
            // Test cases where delegate is overridden and return a CustomTokenTypeValidationError
            // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: SecurityTokenInvalidTypeException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "CustomTokenTypeValidatorDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidTypeException),
                    nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(SecurityTokenInvalidTypeException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: CustomSecurityTokenInvalidTypeException : SecurityTokenInvalidTypeException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "CustomTokenTypeValidatorCustomExceptionDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidTypeException),
                    nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(CustomSecurityTokenInvalidTypeException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "CustomTokenTypeValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomTokenTypeValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // CustomTokenTypeValidationError : TokenTypeValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidTypeException),
                    nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomTokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.CustomTokenTypeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomTokenTypeValidationError.CustomTokenTypeValidationFailureType,
                    typeof(CustomSecurityTokenInvalidTypeException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType),
            });
            #endregion

            #region return TokenTypeValidationError
            // Test cases where delegate is overridden and return an TokenTypeValidationError
            // TokenTypeValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidTypeException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "TokenTypeValidatorDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidTypeException),
                    nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate)),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(SecurityTokenInvalidTypeException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // TokenTypeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidTypeException : SecurityTokenInvalidTypeException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // TokenTypeValidationError does not handle the exception type 'CustomSecurityTokenInvalidTypeException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidTypeException),
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate))),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomTokenTypeExceptionTypeDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(CustomSecurityTokenInvalidTypeException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // TokenTypeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "TokenTypeValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // TokenTypeValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate))),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(
                        nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.TokenTypeValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomTokenTypeValidationDelegates.cs", 0),
                    tokenType)
            });

            // TokenTypeValidationError : ValidationError, ExceptionType: SecurityTokenInvalidTypeException, inner: CustomSecurityTokenInvalidTypeException
            theoryData.Add(new TokenTypeExtensibilityTheoryData(
                "TokenTypeValidatorThrows",
                tokenHandlerType,
                tokenType,
                CustomTokenTypeValidationDelegates.TokenTypeValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidTypeException),
                    string.Format(Tokens.LogMessages.IDX10275),
                    typeof(CustomSecurityTokenInvalidTypeException)),
                ValidationError = new TokenTypeValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10275), null),
                    ValidationFailureType.TokenTypeValidatorThrew,
                    typeof(SecurityTokenInvalidTypeException),
                    new StackFrame("JsonWebTokenHandler.ValidateToken.Internal.cs", 0),
                    tokenType,
                    new SecurityTokenInvalidTypeException(nameof(CustomTokenTypeValidationDelegates.TokenTypeValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
