// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Abstractions;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents an error that occurred during <see cref="SecurityToken"/> validation.
    /// If necessary, it can be used to create an instance of <see cref="Exception"/>.
    /// </summary>
    public class ValidationError : OperationError
    {
        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>.
        /// </summary>
        /// <param name="messageDetail"/>Information that describes the error that occurred.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the error occurred.
        protected internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame)
            : this(messageDetail,
                  validationFailureType,
                  stackFrame,
                  null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>.
        /// </summary>
        /// <param name="messageDetail"/>Information that describes the error that occurred.
        /// <param name="validationFailureType"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the error occurred.
        /// <param name="innerException"/>If present, represents an exception that occurred during validation.
        protected internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailureType,
            StackFrame stackFrame,
            Exception? innerException)
        {
            InnerException = innerException;
            MessageDetail = messageDetail;
            FailureType = validationFailureType;
            StackFrames = new List<StackFrame>(4)
            {
                stackFrame
            };
        }

        /// <summary>
        /// Creates and returns instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public virtual Exception GetException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
            Exception ??= new SecurityTokenValidationException(MessageDetail.Message, this, InnerException);
            return Exception;
        }

        /// <summary>
        /// Gets or sets the exception associated with the current operation.
        /// </summary>
#pragma warning disable CA1721 // Property names should not match get methods
#pragma warning disable RS0016 // Add public types and members to the declared API
        protected Exception? Exception { get; set; }
#pragma warning restore RS0016 // Add public types and members to the declared API
#pragma warning restore CA1721 // Property names should not match get methods

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ValidationError"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        protected virtual Exception CreateException()
#pragma warning restore RS0016 // Add public types and members to the declared API
        {
#pragma warning disable CS8603 // Possible null reference return.
            return null;
#pragma warning restore CS8603 // Possible null reference return.
        }

        /// <summary>
        /// Logs the validation error.
        /// </summary>
        /// <param name="logger">The <see cref="ILogger"/> to be used for logging.</param>
        [CLSCompliant(false)]
        public void Log(ILogger logger)
        {
            if (logger == null)
                throw new ArgumentNullException(nameof(logger));

            Logger.TokenValidationFailed(logger, FailureType.Name, MessageDetail.Message);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ValidationError"/> representing a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <param name="stackFrame">The stack frame where the error occurred.</param>
        /// <returns>A new <see cref="ValidationError"/>.</returns>
        public static ValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            stackFrame,
            null);

        /// <summary>
        /// Gets the type of validation failure that occurred.
        /// </summary>
        public ValidationFailureType FailureType { get; }

        /// <summary>
        /// Gets the inner exception that occurred.
        /// </summary>
        public Exception? InnerException { get; }

        /// <summary>
        /// Gets the message that explains the error.
        /// </summary>
        public string Message => MessageDetail.Message;

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
        public ValidationError AddCurrentStackFrame([CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
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
        public static StackFrame GetCurrentStackFrame(
            [CallerFilePath] string filePath = "", [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
        {
            // String is allocated, but it goes out of scope immediately after the call
            string key = filePath + lineNumber;

            return CachedStackFrames.GetOrAdd(
                key,
                // Need to skip the call to the delegate + GetOrAdd when creating the frame
                _ => new StackFrame(skipFrames + 2, true));
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
                string messageDetail)
            {
                if (logger.IsEnabled(LogLevel.Information))
                {
                    s_tokenValidationFailed(logger, validationFailureType, messageDetail, null);
                }
            }
        }
    }
}
#nullable restore
