// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents an error that occurred during the validation of a <see cref="SecurityToken"/>.
    /// </summary>
    public class ValidationError
    {
        // The CachedStckFrames dictionary contains the cached StackFrames for the entire runtime.
        internal static ConcurrentDictionary<string, StackFrame> CachedStackFrames { get; } = new();

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>.
        /// </summary>
        /// <param name="messageDetail" />Information about the error. Can be used to provide details for error messages.
        /// <param name="validationFailure"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the error occurred.
        protected internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailure,
            StackFrame stackFrame)
            : this(messageDetail,
                  validationFailure,
                  stackFrame,
                  null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>.
        /// </summary>
        /// <param name="messageDetail" />Information about the error. Can be used to provide details for error messages.
        /// <param name="validationFailure"/>The <see cref="ValidationFailureType"/> that occurred.
        /// <param name="stackFrame"/>The stack frame where the error occurred.
        /// <param name="innerException"/>An exception that occurred during validation.
        protected internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType validationFailure,
            StackFrame stackFrame,
            Exception? innerException)
        {
            InnerException = innerException;
            MessageDetail = messageDetail;
            FailureType = validationFailure;
            StackFrames = new List<StackFrame>(4)
            {
                stackFrame
            };
        }

        /// <summary>
        /// Creates and returns instance of an <see cref="Exception"/> using <see cref="FailureType"/>
        /// </summary>
        /// <returns>An instance of an Exception.</returns>
        public virtual Exception GetException()
        {
            if (Exception is not null)
                return Exception;

            if (FailureType == ValidationFailureType.NullArgument)
                Exception = new ArgumentNullException(MessageDetail.Message, InnerException);
            else if (FailureType == ValidationFailureType.TokenDecryptionFailed)
                Exception = new SecurityTokenDecryptionFailedException(MessageDetail.Message, this, InnerException);
            else if (FailureType == ValidationFailureType.KeyWrapFailed)
                Exception = new SecurityTokenKeyWrapException(MessageDetail.Message, this, InnerException);
            else
                Exception = new SecurityTokenValidationException(MessageDetail.Message, this, InnerException);

            return Exception;
        }

        /// <summary>
        /// Gets or sets the exception associated with the <see cref="ValidationError"/>.
        /// </summary>
#pragma warning disable CA1721 // Property names should not match get methods
        public Exception? Exception { get; protected set; }
#pragma warning restore CA1721 // Property names should not match get methods

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
        /// Gets the <see cref="MessageDetail"/> which contains information about the error. Can be used to provide details for error messages.
        /// </summary>
        public MessageDetail MessageDetail { get; }

        /// <summary>
        /// Gets the collection of <see cref="StackFrame"/> instances that represent the call stack locations
        /// where this <see cref="ValidationError"/> was recorded or augmented. This can be used for enhanced
        /// diagnostics and tracing of validation errors, especially in asynchronous or layered validation flows.
        /// </summary>
        public IList<StackFrame> StackFrames { get; }

        /// <summary>
        /// Adds a stack frame to the list of stack frames and returns the updated object.
        /// </summary>
        /// <param name="stackFrame">The <see cref="StackFrame"/> to be added.</param>
        /// <returns>The updated <see cref="ValidationError"/> instance.</returns>
        public ValidationError AddStackFrame(StackFrame stackFrame)
        {
            StackFrames.Add(stackFrame);
            return this;
        }

        /// <summary>
        /// Adds the <see cref="StackFrame"/> to the cache using the key.
        /// If there is no cache entry for the key, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="key">The key for the cached stack frame.</param>
        /// <param name="stackFrame">The <see cref="StackFrame"/> to use as a template if a cached frame does not exist.</param>
        /// <param name="memberName">The name of the calling member. Will be automatically provided by the compiler.</param>
        /// <returns>The <see cref="StackFrame"/>that was found or added.</returns>
        internal static StackFrame GetAsyncStackFrame(
            string key,
            StackFrame stackFrame,
            [CallerMemberName] string memberName = "")
        {
            // GetOrAdd is thread-safe and will only create a new entry if it does not already exist.
            StackFrame cachedFrame = CachedStackFrames.GetOrAdd(key, _ =>
            {
                StackFrame frame = stackFrame ?? new StackFrame(1, true);
                return new IdentityModelStackFrame(
                    frame.GetILOffset(),
                    frame.GetNativeOffset(),
                    frame.GetFileName() ?? string.Empty,
                    frame.GetFileLineNumber(),
                    frame.GetFileColumnNumber(),
                    memberName);
            });

            // Defensive: never return null
            return cachedFrame ?? new StackFrame(0, true);
        }

        /// <summary>
        /// Adds the current stack frame to the list of stack frames and returns the updated object.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="key">The key for the cached stack frame.</param>
        /// <param name="cachedFrame">The <see cref="StackFrame"/>that was found.</param>
        /// <returns>true if found, false otherwise.</returns>
        internal static bool TryGetStackFrame(
            string key,
            out StackFrame? cachedFrame)
        {
            return CachedStackFrames.TryGetValue(key, out cachedFrame);
        }

        /// <summary>
        /// Gets the key for the cached stack frame based on the current member name, file path, and line number.
        /// </summary>
        /// <param name="memberName">The name of the calling member. Will be automatically provided by the compiler by default.</param>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. Captured automatically by default.</param>
        /// <returns>The updated object.</returns>
        internal static string GetStackFrameKey(
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            return memberName + filePath + lineNumber;
        }

        /// <summary>
        /// Adds the current stack frame to the list of stack frames and returns the updated object.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="memberName">The name of the calling member. Will be automatically provided by the compiler by default.</param>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The updated object.</returns>
        internal ValidationError AddCurrentStackFrame(
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0,
            int skipFrames = 1)
        {
            // We add 1 to the skipped frames to skip the current method
            StackFrames.Add(GetCurrentStackFrame(memberName, filePath, lineNumber, skipFrames + 1));
            return this;
        }

        /// <summary>
        /// Returns the stack frame corresponding to the file path and line number from which this method is called.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="memberName">The name of the calling member. Will be automatically provided by the compiler by default.</param>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The captured stack frame.</returns>
        /// <remarks>If this is called from a helper method, consider adding an extra skip frame to avoid capturing the helper instead.</remarks>
        internal static StackFrame
            GetCurrentStackFrame(
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
        {
            return CachedStackFrames.GetOrAdd(
                memberName + filePath + lineNumber,
                _ => new StackFrame(skipFrames + 2, true));
        }
    }
}
#nullable restore
