// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Identity.Abstractions;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents an error that occurred during the validation of a <see cref="SecurityToken"/>.
    /// </summary>
    public class ValidationError : OperationError
    {
        // ConcurrentDictionary is thread-safe and only locks when adding a new item.
        // TODO - is this the right place for this cache?
        // TODO - does this need to be a ConcurrentDictionary?
        private static ConcurrentDictionary<string, StackFrame> CachedStackFrames { get; } = new();

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
        /// Gets the message which contains information about the error. Can be used to provide details for error messages.
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
        /// Adds a <see cref="StackFrame"/> to the list of stack frames and returns the updated object.
        /// </summary>
        /// <param name="stackFrame">
        /// The <see cref="StackFrame"/> to use as a template if a cached frame does not exist.
        /// If <c>null</c>, a new <see cref="StackFrame"/> is created.
        /// </param>
        /// <param name="memberName">
        /// The name of the calling member. Automatically provided by the compiler.
        /// Used as part of the cache key for the stack frame.
        /// </param>
        /// <param name="filePath">
        /// The full path of the source file containing the caller. Automatically provided by the compiler.
        /// Used as part of the cache key for the stack frame.
        /// </param>
        /// <param name="lineNumber">
        /// The line number in the source file at which this method is called. Automatically provided by the compiler.
        /// Used as part of the cache key for the stack frame.
        /// </param>
        /// <returns>
        /// The updated <see cref="ValidationError"/> instance with the new <see cref="StackFrame"/> added to <see cref="StackFrames"/>.
        /// </returns>
        public ValidationError AddAsyncStackFrame(
            StackFrame stackFrame,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            string key = memberName + filePath + lineNumber;
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

            StackFrames.Add(cachedFrame);
            return this;
        }

        /// <summary>
        /// Adds the current stack frame to the list of stack frames and returns the updated object.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="stackFrame"></param>
        /// <param name="memberName"></param>
        /// <param name="filePath"></param>
        /// <param name="lineNumber"></param>
        /// <returns>The updated object.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        internal static StackFrame GetAsyncStackFrame(
#pragma warning restore RS0016 // Add public types and members to the declared API
            StackFrame stackFrame,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            string key = memberName + filePath + lineNumber;
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
        /// <param name="memberName"></param>
        /// <param name="filePath"></param>
        /// <param name="lineNumber"></param>
        /// <param name="cachedFrame"></param>
        /// <returns>The updated object.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        internal static bool TryGetStackFrame(
#pragma warning restore RS0016 // Add public types and members to the declared API
            out StackFrame? cachedFrame,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            string key = memberName + filePath + lineNumber;
            return CachedStackFrames.TryGetValue(key, out cachedFrame);
        }

        /// <summary>
        /// Adds the current stack frame to the list of stack frames and returns the updated object.
        /// If there is no cache entry for the given file path and line number, a new stack frame is created and added to the cache.
        /// </summary>
        /// <param name="memberName"></param>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The updated object.</returns>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public ValidationError AddCurrentStackFrame(
#pragma warning restore RS0016 // Add public types and members to the declared API
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
        /// <param name="memberName"></param>
        /// <param name="filePath">The path to the file from which this method is called. Captured automatically by default.</param>
        /// <param name="lineNumber">The line number from which this method is called. CAptured automatically by default.</param>
        /// <param name="skipFrames">The number of stack frames to skip when capturing. Used to avoid capturing this method and get the caller instead.</param>
        /// <returns>The captured stack frame.</returns>
        /// <remarks>If this is called from a helper method, consider adding an extra skip frame to avoid capturing the helper instead.</remarks>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public static StackFrame
            GetCurrentStackFrame(
#pragma warning restore RS0016 // Add public types and members to the declared API
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0, int skipFrames = 1)
        {
            // String is allocated, but it goes out of scope immediately after the call

            string key = memberName + filePath + lineNumber;

            return CachedStackFrames.GetOrAdd(
                key,
                // Need to skip the call to the delegate + GetOrAdd when creating the frame
                _ => new StackFrame(skipFrames + 2, true));
        }
    }
}
#nullable restore
