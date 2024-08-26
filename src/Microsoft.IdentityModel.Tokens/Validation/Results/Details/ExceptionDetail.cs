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
        /// <param name="MessageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        public ExceptionDetail(MessageDetail MessageDetail, ExceptionType exceptionType, StackFrame stackFrame)
            : this(MessageDetail, exceptionType, stackFrame, null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        public ExceptionDetail(MessageDetail messageDetail, ExceptionType exceptionType, StackFrame stackFrame, Exception innerException)
        {
            Type = exceptionType;
            InnerException = innerException;
            MessageDetail = messageDetail;
            StackFrames = new List<StackFrame>(4)
            {
                stackFrame
            };
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ExceptionDetail"/>
        /// </summary>
        /// <returns>An instantance of an Exception.</returns>
        public Exception GetException()
        {
            Exception exception = ExceptionFromType(Type, InnerException);
            if (exception is SecurityTokenException securityTokenException)
                securityTokenException.ExceptionDetail = this;

            return exception;
        }

        internal static ExceptionDetail NullParameter(string parameterName, StackFrame stackFrame) => new ExceptionDetail(
            MessageDetail.NullParameter(parameterName),
            ExceptionType.ArgumentNull, stackFrame);

        /// <summary>
        /// Gets the type of exception that occurred.
        /// </summary>
        public ExceptionType Type { get; }

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

        private Exception ExceptionFromType(ExceptionType exceptionType, Exception innerException)
        {
            switch (exceptionType)
            {
                case ExceptionType.ArgumentNull:
                    return new ArgumentNullException(MessageDetail.Message, innerException);
                case ExceptionType.InvalidArgument:
                    return new ArgumentException(MessageDetail.Message, innerException);
                case ExceptionType.InvalidOperation:
                    return new InvalidOperationException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityToken:
                    return new SecurityTokenException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenDecompressionFailed:
                    return new SecurityTokenDecompressionFailedException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenDecryptionFailed:
                    return new SecurityTokenDecryptionFailedException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenExpired:
                    return new SecurityTokenExpiredException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidAudience:
                    return new SecurityTokenInvalidAudienceException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidAlgorithm:
                    return new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidIssuer:
                    return new SecurityTokenInvalidIssuerException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidLifetime:
                    return new SecurityTokenInvalidLifetimeException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidSignature:
                    return new SecurityTokenInvalidSignatureException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidSigningKey:
                    return new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidType:
                    return new SecurityTokenInvalidTypeException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenKeyWrap:
                    return new SecurityTokenKeyWrapException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenMalformed:
                    return new SecurityTokenMalformedException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenNoExpiration:
                    return new SecurityTokenNoExpirationException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenNotYetValid:
                    return new SecurityTokenNotYetValidException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenReplayDetected:
                    return new SecurityTokenReplayDetectedException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenReplayAddFailed:
                    return new SecurityTokenReplayAddFailedException(MessageDetail.Message, innerException);
                case ExceptionType.SecurityTokenSignatureKeyNotFound:
                    return new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message, innerException);
                default:
                    throw new ArgumentException("Invalid ExceptionType.");
            }
        }
    }

    internal enum ExceptionType
    {
        Unknown = -1,
        ArgumentNull,
        InvalidArgument,
        InvalidOperation,
        SecurityToken,
        SecurityTokenDecompressionFailed,
        SecurityTokenDecryptionFailed,
        SecurityTokenExpired,
        SecurityTokenInvalidAudience,
        SecurityTokenInvalidAlgorithm,
        SecurityTokenInvalidIssuer,
        SecurityTokenInvalidLifetime,
        SecurityTokenInvalidSigningKey,
        SecurityTokenInvalidSignature,
        SecurityTokenInvalidType,
        SecurityTokenKeyWrap,
        SecurityTokenMalformed,
        SecurityTokenNoExpiration,
        SecurityTokenNotYetValid,
        SecurityTokenReplayDetected,
        SecurityTokenReplayAddFailed,
        SecurityTokenSignatureKeyNotFound,
        ExceptionTypeCount
    }
}
