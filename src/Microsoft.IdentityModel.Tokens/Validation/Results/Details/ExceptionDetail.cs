// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information so that Exceptions can be logged or thrown written as required.
    /// </summary>
    internal class ExceptionDetail
    {
        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        public ExceptionDetail(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame)
            : this(messageDetail, failureType, exceptionType, stackFrame, null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        public ExceptionDetail(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame,
            Exception innerException)
        {
            ExceptionType = exceptionType;
            InnerException = innerException;
            MessageDetail = messageDetail;
            FailureType = failureType;
            StackFrames = new List<StackFrame>(4)
            {
                stackFrame
            };
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ExceptionDetail"/>
        /// </summary>
        /// <returns>An instantance of an Exception.</returns>
        public virtual Exception GetException()
        {
            if (ExceptionType == typeof(ArgumentNullException))
                return new ArgumentNullException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(InvalidOperationException))
                return new InvalidOperationException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(ArgumentException))
                return new ArgumentException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenException))
                return new SecurityTokenException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenDecompressionFailedException))
                return new SecurityTokenDecompressionFailedException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenDecryptionFailedException))
                return new SecurityTokenDecryptionFailedException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenExpiredException))
                return new SecurityTokenExpiredException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidAudienceException))
                return new SecurityTokenInvalidAudienceException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                return new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidIssuerException))
                return new SecurityTokenInvalidIssuerException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidLifetimeException))
                return new SecurityTokenInvalidLifetimeException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidSignatureException))
                return new SecurityTokenInvalidSignatureException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidSigningKeyException))
                return new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenInvalidTypeException))
                return new SecurityTokenInvalidTypeException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenKeyWrapException))
                return new SecurityTokenKeyWrapException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenMalformedException))
                return new SecurityTokenMalformedException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenNoExpirationException))
                return new SecurityTokenNoExpirationException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenNotYetValidException))
                return new SecurityTokenNotYetValidException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenReplayDetectedException))
                return new SecurityTokenReplayDetectedException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenReplayAddFailedException))
                return new SecurityTokenReplayAddFailedException(MessageDetail.Message, InnerException);
            else if (ExceptionType == typeof(SecurityTokenSignatureKeyNotFoundException))
                return new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message, InnerException);
            else
                // TODO - We need to make sure that all System exceptions THAT WE THROW are accounted for here.
                return new ArgumentException("Invalid typeof");
        }

        internal static ExceptionDetail NullParameter(string parameterName, StackFrame stackFrame) => new ExceptionDetail(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(ArgumentNullException),
            stackFrame);

        /// <summary>
        /// Gets the type of validation failure that occurred.
        /// </summary>
        public ValidationFailureType FailureType { get; }

        /// <summary>
        /// Gets the type of exception that occurred.
        /// </summary>
        public Type ExceptionType { get; }

        /// <summary>
        /// Gets the inner exception that occurred.
        /// </summary>
        public Exception InnerException { get; }

        /// <summary>
        /// Gets the message details that are used to generate the exception message.
        /// </summary>
        public MessageDetail MessageDetail { get; }

        /// <summary>
        /// Gets the stack frames where the exception occurred.
        /// </summary>
        public IList<StackFrame> StackFrames { get; }

        /// <summary>
        /// Adds a stack frame to the list of stack frames and returns the updated object.
        /// </summary>
        /// <param name="stackFrame">The <see cref="StackFrame"/> to be added.</param>
        /// <returns></returns>
        public ExceptionDetail AddStackFrame(StackFrame stackFrame)
        {
            StackFrames.Add(stackFrame);
            return this;
        }
    }
}
