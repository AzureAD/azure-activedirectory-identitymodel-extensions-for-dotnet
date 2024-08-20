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
        public Exception GetException() => ExceptionFromType(Type, MessageDetail, InnerException);

        internal static ExceptionDetail NullParameter(string parameterName) => new ExceptionDetail(
            MessageDetail.NullParameter(parameterName),
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

        public static Exception ExceptionFromType(
            ValidationErrorType exceptionType,
            MessageDetail messageDetail,
            Exception innerException)
        {
            switch (exceptionType)
            {
                case ValidationErrorType.ArgumentNull:
                    return new ArgumentNullException(messageDetail.Message, innerException);
                case ValidationErrorType.InvalidArgument:
                    return new ArgumentException(messageDetail.Message, innerException);
                case ValidationErrorType.InvalidOperation:
                    return new InvalidOperationException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityToken:
                    return new SecurityTokenException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenDecompressionFailed:
                    return new SecurityTokenDecompressionFailedException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenDecryptionFailed:
                    return new SecurityTokenDecryptionFailedException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenExpired:
                    return new SecurityTokenExpiredException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidAudience:
                    return new SecurityTokenInvalidAudienceException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidAlgorithm:
                    return new SecurityTokenInvalidAlgorithmException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidIssuer:
                    return new SecurityTokenInvalidIssuerException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidLifetime:
                    return new SecurityTokenInvalidLifetimeException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidSignature:
                    return new SecurityTokenInvalidSignatureException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidSigningKey:
                    return new SecurityTokenInvalidSigningKeyException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenInvalidType:
                    return new SecurityTokenInvalidTypeException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenKeyWrap:
                    return new SecurityTokenKeyWrapException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenMalformed:
                    return new SecurityTokenMalformedException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenNoExpiration:
                    return new SecurityTokenNoExpirationException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenNotYetValid:
                    return new SecurityTokenNotYetValidException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenReplayDetected:
                    return new SecurityTokenReplayDetectedException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenReplayAddFailed:
                    return new SecurityTokenReplayAddFailedException(messageDetail.Message, innerException);
                case ValidationErrorType.SecurityTokenSignatureKeyNotFound:
                    return new SecurityTokenSignatureKeyNotFoundException(messageDetail.Message, innerException);
                default:
                    throw new ArgumentException("Invalid ExceptionType.");
            }
        }
    }
}
