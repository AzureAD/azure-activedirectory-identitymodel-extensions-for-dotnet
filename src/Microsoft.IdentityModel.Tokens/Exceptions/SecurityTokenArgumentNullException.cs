// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
#if !NET8_0_OR_GREATER
using System.Text;
#endif

#nullable enable

namespace Microsoft.IdentityModel.Tokens
{
    internal class SecurityTokenArgumentNullException : ArgumentNullException, ISecurityTokenException
    {
        private string? _stackTrace;
        private ValidationError? _validationError;

        public SecurityTokenArgumentNullException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenArgumentNullException"/> class with a specified null parameter.
        /// </summary>
        /// <param name="paramName">The name of the null parameter that triggered the exception.</param>
        public SecurityTokenArgumentNullException(string? paramName)
            : base(paramName)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenArgumentNullException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The <see cref="Exception"/> that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public SecurityTokenArgumentNullException(string? message, Exception? innerException)
            : base(message, innerException)
        {
        }

        public SecurityTokenArgumentNullException(string? paramName, string? message)
            : base(paramName, message)
        {
        }

        public void SetValidationError(ValidationError validationError)
        {
            _validationError = validationError;
        }


        /// <summary>
        /// Gets the stack trace that is captured when the exception is created.
        /// </summary>
        public override string? StackTrace
        {
            get
            {
                if (_stackTrace == null)
                {
                    if (_validationError == null)
                        return base.StackTrace;
#if NET8_0_OR_GREATER
                    _stackTrace = new StackTrace(_validationError.StackFrames).ToString();
#else
                    StringBuilder sb = new();
                    foreach (StackFrame frame in _validationError.StackFrames)
                    {
                        sb.Append(frame.ToString());
                        sb.Append(Environment.NewLine);
                    }

                    _stackTrace = sb.ToString();
#endif
                }

                return _stackTrace;
            }
        }
    }
}
#nullable restore
