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
        public static TheoryData<LifetimeExtensibilityTheoryData> GenerateLifetimeExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            TheoryData<LifetimeExtensibilityTheoryData> theoryData = new();
            CallContext callContext = new CallContext();
            DateTime utcNow = DateTime.UtcNow;
            DateTime utcPlusOneHour = utcNow.AddHours(1);

            #region return CustomLifetimeValidationError
            // Test cases where delegate is overridden and return a CustomLifetimeValidationError
            // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: SecurityTokenInvalidLifetimeException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "CustomLifetimeValidatorDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidLifetimeException),
                    nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate)),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(SecurityTokenInvalidLifetimeException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour)
            });

            // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: CustomSecurityTokenInvalidLifetimeException : SecurityTokenInvalidLifetimeException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "CustomLifetimeValidatorCustomExceptionDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate)),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour),
            });

            // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "CustomLifetimeValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomLifetimeValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour),
            });

            // CustomLifetimeValidationError : LifetimeValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomLifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.CustomLifetimeValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomLifetimeValidationError.CustomLifetimeValidationFailureType,
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour),
            });
            #endregion

            #region return LifetimeValidationError
            // Test cases where delegate is overridden and return an LifetimeValidationError
            // LifetimeValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidLifetimeException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "LifetimeValidatorDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.LifetimeValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidLifetimeException),
                    nameof(CustomLifetimeValidationDelegates.LifetimeValidatorDelegate)),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(SecurityTokenInvalidLifetimeException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour)
            });

            // LifetimeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidLifetimeException : SecurityTokenInvalidLifetimeException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "LifetimeValidatorCustomLifetimeExceptionTypeDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // LifetimeValidationError does not handle the exception type 'CustomSecurityTokenInvalidLifetimeException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidLifetimeException),
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate))),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomLifetimeExceptionTypeDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(CustomSecurityTokenInvalidLifetimeException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour)
            });

            // LifetimeValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "LifetimeValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // LifetimeValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate))),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(
                        nameof(CustomLifetimeValidationDelegates.LifetimeValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.LifetimeValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomLifetimeValidationDelegates.cs", 0),
                    utcNow,
                    utcPlusOneHour)
            });

            // LifetimeValidationError : ValidationError, ExceptionType: SecurityTokenInvalidLifetimeException, inner: CustomSecurityTokenInvalidLifetimeException
            theoryData.Add(new LifetimeExtensibilityTheoryData(
                "LifetimeValidatorThrows",
                tokenHandlerType,
                utcNow,
                CustomLifetimeValidationDelegates.LifetimeValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidLifetimeException),
                    string.Format(Tokens.LogMessages.IDX10271),
                    typeof(CustomSecurityTokenInvalidLifetimeException)),
                ValidationError = new LifetimeValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10271), null),
                    ValidationFailureType.LifetimeValidatorThrew,
                    typeof(SecurityTokenInvalidLifetimeException),
                    new StackFrame(stackFrameFileName, 0),
                    utcNow,
                    utcPlusOneHour,
                    new SecurityTokenInvalidLifetimeException(nameof(CustomLifetimeValidationDelegates.LifetimeValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
