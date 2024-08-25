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
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        public ExceptionDetail(MessageDetail messageDetail, ExceptionType exceptionType, StackFrame stackFrame)
            : this(messageDetail, exceptionType, stackFrame, null)
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
            Exception exception = ExceptionFromType(Type, MessageDetail, InnerException);
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

        public static Exception ExceptionFromType(
            ExceptionType exceptionType,
            MessageDetail messageDetail,
            Exception innerException)
        {
            switch (exceptionType)
            {
                case ExceptionType.ArgumentNull:
                    return new ArgumentNullException(messageDetail.Message, innerException);
                case ExceptionType.InvalidArgument:
                    return new ArgumentException(messageDetail.Message, innerException);
                case ExceptionType.InvalidOperation:
                    return new InvalidOperationException(messageDetail.Message, innerException);
                case ExceptionType.SecurityToken:
                    return new SecurityTokenException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenDecompressionFailed:
                    return new SecurityTokenDecompressionFailedException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenDecryptionFailed:
                    return new SecurityTokenDecryptionFailedException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenExpired:
                    return new SecurityTokenExpiredException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidAudience:
                    return new SecurityTokenInvalidAudienceException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidAlgorithm:
                    return new SecurityTokenInvalidAlgorithmException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidIssuer:
                    return new SecurityTokenInvalidIssuerException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidLifetime:
                    return new SecurityTokenInvalidLifetimeException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidSignature:
                    return new SecurityTokenInvalidSignatureException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidSigningKey:
                    return new SecurityTokenInvalidSigningKeyException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenInvalidType:
                    return new SecurityTokenInvalidTypeException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenKeyWrap:
                    return new SecurityTokenKeyWrapException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenMalformed:
                    return new SecurityTokenMalformedException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenNoExpiration:
                    return new SecurityTokenNoExpirationException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenNotYetValid:
                    return new SecurityTokenNotYetValidException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenReplayDetected:
                    return new SecurityTokenReplayDetectedException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenReplayAddFailed:
                    return new SecurityTokenReplayAddFailedException(messageDetail.Message, innerException);
                case ExceptionType.SecurityTokenSignatureKeyNotFound:
                    return new SecurityTokenSignatureKeyNotFoundException(messageDetail.Message, innerException);
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
