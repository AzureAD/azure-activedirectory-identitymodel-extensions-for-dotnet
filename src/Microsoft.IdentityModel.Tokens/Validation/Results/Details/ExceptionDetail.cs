// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information so that Exceptions can be logged or thrown written as required.
    /// </summary>
    internal class ExceptionDetail
    {
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
        private Type _exceptionType;

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="MessageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        public ExceptionDetail(
            MessageDetail MessageDetail,
            ValidationFailureType failureType,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type exceptionType,
            StackFrame stackFrame)
            : this(MessageDetail, failureType, exceptionType, stackFrame, innerException: null)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the exception that is used to generate the exception message.
        /// <param name="exceptionType"/> is the type of exception that occurred.
        /// <param name="failureType"/> is the type of validation failure that occurred.
        /// <param name="stackFrame"/> is the stack frame where the exception occurred.
        /// <param name="innerException"/> is the inner exception that occurred.
        public ExceptionDetail(
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

        public ExceptionDetail(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type exceptionType,
            StackFrame stackFrame,
            ExceptionDetail innerExceptionDetail)
        {
            InnerExceptionDetail = innerExceptionDetail;
            MessageDetail = messageDetail;
            _exceptionType = exceptionType;
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
        public Exception GetException()
        {
            Exception exception;
            if (InnerException == null && InnerExceptionDetail == null)
                exception = Activator.CreateInstance(_exceptionType, MessageDetail.Message) as Exception;
            else
                exception = Activator.CreateInstance(
                    _exceptionType,
                    MessageDetail.Message,
                    InnerException ?? InnerExceptionDetail.GetException()) as Exception;

            if (exception is SecurityTokenException securityTokenException)
                securityTokenException.ExceptionDetail = this;

            AddAdditionalInformation(exception);

            return exception;
        }

        protected virtual void AddAdditionalInformation(Exception exception)
        {
            // base implementation is no-op. Derived classes can override to add additional information to the exception.
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
        public Type ExceptionType => _exceptionType;

        /// <summary>
        /// Gets the inner exception that occurred.
        /// </summary>
        public Exception InnerException { get; }

        /// <summary>
        /// Gets the details for the inner exception that occurred.
        /// </summary>
        public ExceptionDetail InnerExceptionDetail { get; }

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
