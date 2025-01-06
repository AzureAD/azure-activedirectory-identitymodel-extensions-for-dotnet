// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using System.Collections.Generic;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public partial class ExtensibilityTesting
    {
        public static TheoryData<AudienceExtensibilityTheoryData> GenerateAudienceExtensibilityTestCases(
            string tokenHandlerType,
            int extraStackFrames,
            string stackFrameFileName)
        {
            var theoryData = new TheoryData<AudienceExtensibilityTheoryData>();
            CallContext callContext = new CallContext();
            string issuerGuid = Guid.NewGuid().ToString();
            var audience = Default.Audience;
            List<String> tokenAudiences = [audience];

            #region return CustomAudienceValidationError
            // Test cases where delegate is overridden and return a CustomAudienceValidationError
            // CustomAudienceValidationError : AudienceValidationError, ExceptionType: SecurityTokenInvalidAudienceException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "CustomAudienceValidatorDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidAudienceException),
                    nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(SecurityTokenInvalidAudienceException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null)
            });

            // CustomAudienceValidationError : AudienceValidationError, ExceptionType: CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "CustomAudienceValidatorCustomExceptionDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null),
            });

            // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "CustomAudienceValidatorUnknownExceptionDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate,
                extraStackFrames: extraStackFrames)
            {
                // CustomAudienceValidationError does not handle the exception type 'NotSupportedException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(NotSupportedException),
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate))),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorUnknownExceptionDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(NotSupportedException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null),
            });

            // CustomAudienceValidationError : AudienceValidationError, ExceptionType: NotSupportedException : SystemException, ValidationFailureType: CustomAudienceValidationFailureType
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate)),
                ValidationError = new CustomAudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.CustomAudienceValidatorCustomExceptionCustomFailureTypeDelegate), null),
                    CustomAudienceValidationError.CustomAudienceValidationFailureType,
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null) // validAudiences
            });
            #endregion

            #region return AudienceValidationError
            // Test cases where delegate is overridden and return an AudienceValidationError
            // AudienceValidationError : ValidationError, ExceptionType:  SecurityTokenInvalidAudienceException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "AudienceValidatorDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.AudienceValidatorDelegate,
                extraStackFrames: extraStackFrames)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidAudienceException),
                    nameof(CustomAudienceValidationDelegates.AudienceValidatorDelegate)),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(SecurityTokenInvalidAudienceException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null)
            });

            // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "AudienceValidatorCustomAudienceExceptionTypeDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // AudienceValidationError does not handle the exception type 'CustomSecurityTokenInvalidAudienceException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenInvalidAudienceException),
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate))),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomAudienceExceptionTypeDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(CustomSecurityTokenInvalidAudienceException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null)
            });

            // AudienceValidationError : ValidationError, ExceptionType:  CustomSecurityTokenException : SystemException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "AudienceValidatorCustomExceptionTypeDelegate",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate,
                extraStackFrames: extraStackFrames)
            {
                // AudienceValidationError does not handle the exception type 'CustomSecurityTokenException'
                ExpectedException = ExpectedException.SecurityTokenException(
                    LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX10002, // "IDX10002: Unknown exception type returned. Type: '{0}'. Message: '{1}'.";
                        typeof(CustomSecurityTokenException),
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate))),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(
                        nameof(CustomAudienceValidationDelegates.AudienceValidatorCustomExceptionTypeDelegate), null),
                    ValidationFailureType.AudienceValidationFailed,
                    typeof(CustomSecurityTokenException),
                    new StackFrame("CustomAudienceValidationDelegates.cs", 0),
                    tokenAudiences,
                    null)
            });

            // AudienceValidationError : ValidationError, ExceptionType: SecurityTokenInvalidAudienceException, inner: CustomSecurityTokenInvalidAudienceException
            theoryData.Add(new AudienceExtensibilityTheoryData(
                "AudienceValidatorThrows",
                tokenHandlerType,
                audience,
                CustomAudienceValidationDelegates.AudienceValidatorThrows,
                extraStackFrames: extraStackFrames - 1)
            {
                ExpectedException = new ExpectedException(
                    typeof(SecurityTokenInvalidAudienceException),
                    string.Format(Tokens.LogMessages.IDX10270),
                    typeof(CustomSecurityTokenInvalidAudienceException)),
                ValidationError = new AudienceValidationError(
                    new MessageDetail(
                        string.Format(Tokens.LogMessages.IDX10270), null),
                    ValidationFailureType.AudienceValidatorThrew,
                    typeof(SecurityTokenInvalidAudienceException),
                    new StackFrame(stackFrameFileName, 0),
                    tokenAudiences,
                    null,
                    new SecurityTokenInvalidAudienceException(nameof(CustomAudienceValidationDelegates.AudienceValidatorThrows))
                )
            });
            #endregion

            return theoryData;
        }
    }
}
#nullable restore
