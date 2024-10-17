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
    internal class ValidationError
    {
        private Type _exceptionType;

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>
        /// </summary>
        /// <param name="MessageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        internal ValidationError(
            MessageDetail MessageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame)
            : this(MessageDetail, failureType, exceptionType, stackFrame, null)
        {
            // TODO: need to include CallContext.
        }

        /// <summary>
        /// Creates an instance of <see cref="ValidationError"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame,
            Exception innerException)
        {
            InnerException = innerException;
            MessageDetail = messageDetail;
            _exceptionType = exceptionType;
            FailureType = failureType;
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

        internal Exception GetException(Type exceptionType, Exception innerException)
        {
            Exception exception = null;

            if (innerException == null && InnerValidationError == null)
            {
                if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    return new SecurityTokenArgumentNullException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidAudienceException))
                    exception = new SecurityTokenInvalidAudienceException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message);
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
                else
                {
                    // Exception type is unknown
                    var message = LogHelper.FormatInvariant(LogMessages.IDX10002, exceptionType, MessageDetail.Message);
                    exception = new SecurityTokenException(message);
                }
            }
            else
            {
                Exception actualException = innerException ?? InnerValidationError.GetException();

                if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    return new SecurityTokenArgumentNullException(MessageDetail.Message, innerException);
                else if (exceptionType == typeof(SecurityTokenInvalidAudienceException))
                    exception = new SecurityTokenInvalidAudienceException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenReplayAddFailedException))
                    exception = new SecurityTokenReplayAddFailedException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidSigningKeyException))
                    exception = new SecurityTokenInvalidSigningKeyException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidTypeException))
                    exception = new SecurityTokenInvalidTypeException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenReplayDetectedException))
                    exception = new SecurityTokenReplayDetectedException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenExpiredException))
                    exception = new SecurityTokenExpiredException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenNotYetValidException))
                    exception = new SecurityTokenNotYetValidException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidLifetimeException))
                    exception = new SecurityTokenInvalidLifetimeException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenNoExpirationException))
                    exception = new SecurityTokenNoExpirationException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidIssuerException))
                    exception = new SecurityTokenInvalidIssuerException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenSignatureKeyNotFoundException))
                    exception = new SecurityTokenSignatureKeyNotFoundException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenDecryptionFailedException))
                    exception = new SecurityTokenDecryptionFailedException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenMalformedException))
                    exception = new SecurityTokenMalformedException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidSignatureException))
                    exception = new SecurityTokenInvalidSignatureException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenArgumentNullException))
                    exception = new SecurityTokenArgumentNullException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                    exception = new SecurityTokenInvalidAlgorithmException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenException))
                    exception = new SecurityTokenException(MessageDetail.Message, actualException);
                else if (exceptionType == typeof(SecurityTokenKeyWrapException))
                    exception = new SecurityTokenKeyWrapException(MessageDetail.Message, actualException);
                else
                {
                    // Exception type is unknown
                    var message = LogHelper.FormatInvariant(LogMessages.IDX10002, exceptionType, MessageDetail.Message);
                    exception = new SecurityTokenException(message, actualException);
                }
            }

            return exception;
        }

        internal static ValidationError NullParameter(string parameterName, StackFrame stackFrame) => new(
            MessageDetail.NullParameter(parameterName),
            ValidationFailureType.NullArgument,
            typeof(SecurityTokenArgumentNullException),
            stackFrame);

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
        public Exception InnerException { get; }

        /// <summary>
        /// Gets the details for the inner exception that occurred.
        /// </summary>
        public ValidationError InnerValidationError { get; }

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
    }
}
