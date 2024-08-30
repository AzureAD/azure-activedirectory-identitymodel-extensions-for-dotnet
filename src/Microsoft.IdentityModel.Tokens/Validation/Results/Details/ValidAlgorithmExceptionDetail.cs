// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information so that Exceptions can be logged or thrown written as required.
    /// </summary>
    internal class ValidAlgorithmExceptionDetail : ExceptionDetail
    {
        /// <summary>
        /// Creates an instance of <see cref="ExceptionDetail"/>
        /// </summary>
        /// <param name="messageDetail"/> contains information about the error that can be used to generate the exception message and logs.
        /// <param name="failureType"/> the validation failure that occurred.
        /// <param name="exceptionType"/> the type of exception that occurred.
        /// <param name="stackFrame"/> the <see cref="StackFrame"/>failure occurred.
        /// <param name="innerException"/> the inner exception may be null.
        /// <param name="invalidAlgorithm"/> the algorithm that was found to be invalid.
        public ValidAlgorithmExceptionDetail(
            MessageDetail messageDetail,
            ValidationFailureType failureType,
            Type exceptionType,
            StackFrame stackFrame,
            Exception innerException,
            string invalidAlgorithm)
            : base(messageDetail, failureType, exceptionType, stackFrame, innerException)
        {
            InvalidAlgorithm = invalidAlgorithm;
        }

        public string InvalidAlgorithm { get; }

        /// <summary>
        /// Creates an instance of an <see cref="Exception"/> using <see cref="ExceptionDetail"/>
        /// </summary>
        /// <returns>An instantance of an Exception.</returns>
        public override Exception GetException()
        {
            return ExceptionFromType(ExceptionType, InnerException);
        }

        private Exception ExceptionFromType(Type exceptionType, Exception innerException)
        {
            if (exceptionType == typeof(SecurityTokenInvalidAlgorithmException))
                return new SecurityTokenInvalidAlgorithmException(this, innerException) { InvalidAlgorithm = InvalidAlgorithm };
            else
                return base.GetException();
        }
    }
}
