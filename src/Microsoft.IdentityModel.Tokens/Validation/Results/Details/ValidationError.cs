// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.IdentityModel.Tokens
{
    internal interface ISecurityTokenException
    {
        void SetValidationError(ValidationError validationError);
    }

    /// <summary>
    /// Contains information so that Exceptions can be logged or thrown written as required.
    /// </summary>
    public class ValidationError
    {
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
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
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type exceptionType,
            StackFrame stackFrame)
            : this(MessageDetail, failureType, exceptionType, stackFrame, innerException: null)
        {
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
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type exceptionType,
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

        internal ValidationError(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type exceptionType,
            StackFrame stackFrame,
            ValidationError innerValidationError)
        {
            InnerValidationError = innerValidationError;
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
        /// <returns>An instantance of an Exception.</returns>
        public Exception GetException()
        {
            Exception exception;
            if (InnerException == null && InnerValidationError == null)
                exception = Activator.CreateInstance(_exceptionType, MessageDetail.Message) as Exception;
            else
                exception = Activator.CreateInstance(
                    _exceptionType,
                    MessageDetail.Message,
                    InnerException ?? InnerValidationError.GetException()) as Exception;

            if (exception is ISecurityTokenException securityTokenException)
            {
                securityTokenException.SetValidationError(this);
                AddAdditionalInformation(securityTokenException);
            }

            return exception;
        }

        /// <summary>
        /// Allows derived classes to add additional information to the exception after instantiating it.
        /// </summary>
        /// <param name="exception">The newly instantiated exception.</param>
        internal virtual void AddAdditionalInformation(ISecurityTokenException exception)
        {
            // base implementation is no-op. Derived classes can override to add additional information to the exception.
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
