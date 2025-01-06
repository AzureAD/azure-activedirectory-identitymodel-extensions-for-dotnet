// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information so that Exceptions can be logged or thrown written as required.
    /// </summary>
    internal class ValidationError
    {
        private Type _exceptionType;

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="validationFailureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            Type exceptionType,
            StackFrame stackFrame,
            Exception? innerException = null)
        {
            InnerException = innerException;
            MessageDetail = messageDetail;
            _exceptionType = exceptionType;
            FailureType = validationFailureType;
            StackFrames = new List<StackFrame>(4)
            {
                stackFrame
            };
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        internal virtual Exception GetException()
        {
            return GetException(ExceptionType, InnerException);
        }

        internal Exception GetException(Type exceptionType, Exception? innerException)
        {
            Exception? exception = null;

            if (innerException is null)
            {
                if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    exception = new SecurityTokenArgumentNullException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidAudienceException))
                    exception = new SecurityTokenInvalidAudienceException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidOperationException))
                    exception = new SecurityTokenInvalidOperationException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenReplayAddFailedException))
                    exception = new SecurityTokenReplayAddFailedException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidSigningKeyException))
                    exception = new SecurityTokenInvalidSigningKeyException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidTypeException))
                    exception = new SecurityTokenInvalidTypeException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenExpiredException))
                    exception = new SecurityTokenExpiredException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenNotYetValidException))
                    exception = new SecurityTokenNotYetValidException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenNoExpirationException))
                    exception = new SecurityTokenNoExpirationException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenSignatureKeyNotFoundException))
                    exception = new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenDecryptionFailedException))
                    exception = new SecurityTokenDecryptionFailedException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenMalformedException))
                    exception = new SecurityTokenMalformedException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidSignatureException))
                    exception = new SecurityTokenInvalidSignatureException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    exception = new SecurityTokenArgumentNullException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenException))
                    exception = new SecurityTokenException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenKeyWrapException))
                    exception = new SecurityTokenKeyWrapException(MessageDetail.Message);
                else if (ExceptionType == typeof(SecurityTokenValidationException))
                    exception = new SecurityTokenValidationException(MessageDetail.Message);
                else
                {
                    // Exception type is unknown
                    var message = LogHelper.FormatInvariant(LogMessages.IDX10002, exceptionType, MessageDetail.Message);
                    exception = new SecurityTokenException(message);
                }
            }
            else
            {
                if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    exception = new SecurityTokenArgumentNullException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidAudienceException))
                    exception = new SecurityTokenInvalidAudienceException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidOperationException))
                    exception = new SecurityTokenInvalidOperationException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenReplayAddFailedException))
                    exception = new SecurityTokenReplayAddFailedException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidSigningKeyException))
                    exception = new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidTypeException))
                    exception = new SecurityTokenInvalidTypeException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenExpiredException))
                    exception = new SecurityTokenExpiredException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenNotYetValidException))
                    exception = new SecurityTokenNotYetValidException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenNoExpirationException))
                    exception = new SecurityTokenNoExpirationException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenSignatureKeyNotFoundException))
                    exception = new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenDecryptionFailedException))
                    exception = new SecurityTokenDecryptionFailedException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenMalformedException))
                    exception = new SecurityTokenMalformedException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidSignatureException))
                    exception = new SecurityTokenInvalidSignatureException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    exception = new SecurityTokenArgumentNullException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenException))
                    exception = new SecurityTokenException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenKeyWrapException))
                    exception = new SecurityTokenKeyWrapException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenValidationException))
                    exception = new SecurityTokenValidationException(MessageDetail.Message, innerException);
                else
                {
                    // Exception type is unknown
                    var message = LogHelper.FormatInvariant(LogMessages.IDX10002, exceptionType, MessageDetail.Message);
                    exception = new SecurityTokenException(message, innerException);
                }
            }

            if (exception is SecurityTokenException securityTokenException)
                securityTokenException.SetValidationError(this);
            else if (exception is SecurityTokenArgumentNullException securityTokenArgumentNullException)
                securityTokenArgumentNullException.SetValidationError(this);

            return exception;
        }

        internal void Log(ILogger logger)
        {
            Logger.TokenValidationFailed(logger, FailureType.Name, MessageDetail.Message);
        }

        internal static ValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame,
            null);

        /// <summary>
        /// Gets the type of validation failure that occurred.
        /// </summary>
        internal ValidationFailureType FailureType { get; }

        /// <summary>
        /// Gets the type of exception that occurred.
        /// </summary>
        public Type ExceptionType => _exceptionType;

        /// <summary>
        /// Gets the inner exception that occurred.
        /// </summary>
        public Exception? InnerException { get; }

        /// <summary>
        /// Gets the message details that are used to generate the exception message.
        /// </summary>
        internal MessageDetail MessageDetail { get; }

        /// <summary>
        /// Gets the stack frames where the exception occurred.
        /// </summary>
        public IList<StackFrame> StackFrames { get; }

        /// <summary>
        /// Adds a stack frame to the list of stack frames and returns the updated object.
        /// </summary>
        /// <param name="stackFrame">The <see cref="StackFrame"/> to be added.</param>
        /// <returns></returns>
        public ValidationError AddStackFrame(StackFrame stackFrame)
        {
            StackFrames.Add(stackFrame);
            return this;
        }

        /// <summary>
        /// Adds the current stack frame to the list of stack frames and returns the updated object.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The updated object.</returns>
        internal ValidationError AddCurrentStackFrame([CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
        {
            // We add 1 to the skipped frames to skip the current method
            StackFrames.Add(GetCurrentStackFrame(filePath, lineNumber, skipFrames + 1));
            return this;
        }

        /// <summary>
        /// Returns the stack frame corresponding to the file path and line number from which this method is called.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The captured stack frame.</returns>
        /// <remarks>If this is called from a helper method, consider adding an extra skip frame to avoid capturing the helper instead.</remarks>
        internal static StackFrame GetCurrentStackFrame(
            [CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
        {
            // String is allocated, but it goes out of scope immediately after the call
            string key = filePath + lineNumber;
            StackFrame frame = CachedStackFrames.GetOrAdd(key, new StackFrame(skipFrames, true));
            return frame;
        }

        // ConcurrentDictionary is thread-safe and only locks when adding a new item.
        private static ConcurrentDictionary<string, StackFrame> CachedStackFrames { get; } = new();

        private static class Logger
        {
            private static readonly Action<ILogger, string, string, Exception?> s_tokenValidationFailed =
                LoggerMessage.Define<string, string>(
                    LogLevel.Information,
                    LoggingEventId.TokenValidationFailed,
                    "[MsIdentityModel] The token validation was unsuccessful due to: {ValidationFailureType} " +
                    "Error message provided: {ValidationErrorMessage}");

            /// <summary>
            /// Logger for handling failures in token validation.
            /// </summary>
            /// <param name="logger">ILogger.</param>
            /// <param name="validationFailureType">The cause of the failure.</param>
            /// <param name="messageDetail">The message provided as part of the failure.</param>
            public static void TokenValidationFailed(
                ILogger logger,
                string validationFailureType,
                string messageDetail) => s_tokenValidationFailed(logger, validationFailureType, messageDetail, null);
        }
    }
}
#nullable restore
