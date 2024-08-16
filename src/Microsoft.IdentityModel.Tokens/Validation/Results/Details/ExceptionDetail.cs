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
        public ExceptionDetail(MessageDetail messageDetail, ValidationErrorType exceptionType)
            : this(messageDetail, exceptionType, null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <paramref name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <paramref name="exceptionType"/> is the type of exception that occurred.
        /// <paramref name="innerException"/> is the inner exception that occurred.
        public ExceptionDetail(MessageDetail messageDetail, ValidationErrorType exceptionType, Exception innerException)
        {
            Type = exceptionType;
            InnerException = innerException;
            MessageDetail = messageDetail;
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
            ValidationErrorType.ArgumentNull);

        /// <summary>
        /// Gets the type of exception that occurred.
        /// </summary>
        public ValidationErrorType Type { get; }

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

        public Exception ExceptionFromType(ValidationErrorType exceptionType, Exception innerException)
        {
            switch (exceptionType)
            {
                case ValidationErrorType.ArgumentNull:
                    return new ArgumentNullException(MessageDetail.Message, innerException);
                case ValidationErrorType.InvalidOperation:
                    return new InvalidOperationException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityToken:
                    return new SecurityTokenException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenDecompressionFailed:
                    return new SecurityTokenDecompressionFailedException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenDecryptionFailed:
                    return new SecurityTokenDecryptionFailedException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenExpired:
                    return new SecurityTokenExpiredException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidAudience:
                    return new SecurityTokenInvalidAudienceException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidAlgorithm:
                    return new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidIssuer:
                    return new SecurityTokenInvalidIssuerException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidLifetime:
                    return new SecurityTokenInvalidLifetimeException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidSignature:
                    return new SecurityTokenInvalidSignatureException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidSigningKey:
                    return new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidType:
                    return new SecurityTokenInvalidTypeException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenKeyWrap:
                    return new SecurityTokenKeyWrapException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenMalformed:
                    return new SecurityTokenMalformedException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenNoExpiration:
                    return new SecurityTokenNoExpirationException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenNotYetValid:
                    return new SecurityTokenNotYetValidException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenReplayDetected:
                    return new SecurityTokenReplayDetectedException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenReplayAddFailed:
                    return new SecurityTokenReplayAddFailedException(MessageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenSignatureKeyNotFound:
                    return new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message, innerException);
                default:
                    throw new ArgumentException("Invalid ExceptionType.");
            }
        }
    }
}
