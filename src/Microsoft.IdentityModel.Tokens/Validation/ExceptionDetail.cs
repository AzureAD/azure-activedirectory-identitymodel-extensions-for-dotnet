// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;

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
        /// <paramref name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <paramref name="exceptionType"/> is the type of exception that occurred.
        /// <paramref name="stackFrame"/> contains information about the stack frame where the exception occurred.
        public ExceptionDetail(MessageDetail messageDetail, ExceptionType exceptionType, StackFrame stackFrame)
            : this(messageDetail, exceptionType, stackFrame, null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <paramref name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <paramref name="exceptionType"/> is the type of exception that occurred.
        /// <paramref name="stackFrame"/> contains information about the stack frame where the exception occurred.
        /// <paramref name="innerException"/> is the inner exception that occurred.
        public ExceptionDetail(MessageDetail messageDetail, ExceptionType exceptionType, StackFrame stackFrame, Exception innerException)
        {
            Type = exceptionType;
            InnerException = innerException;
            MessageDetail = messageDetail;
            StackFrames.Add(stackFrame);
        }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ExceptionDetail"/>
        /// </summary>
        /// <returns>An instantance of an Exception.</returns>
        public Exception GetException() => ExceptionFromType(Type, InnerException);

        internal static ExceptionDetail NullParameter(string parameterName) => new ExceptionDetail(
            new MessageDetail(
                LogMessages.IDX10000,
                LogHelper.MarkAsNonPII(parameterName)),
            ExceptionType.ArgumentNull,
            new StackFrame());

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
        public IList<StackFrame> StackFrames { get; } = [];

        public enum ExceptionType
        {
            Unknown = -1,
            ArgumentNull,
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
        }

        private Exception ExceptionFromType(ExceptionType exceptionType, Exception innerException)
        {
            switch (exceptionType)
            {
                case ExceptionType.ArgumentNull:
                    return new ArgumentNullException(MessageDetail.Message, innerException);
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
}
