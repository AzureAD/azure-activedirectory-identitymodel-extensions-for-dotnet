// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.Serialization;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Throw this exception when a received <see cref="SecurityToken"/> has invalid arguments.
    /// </summary>
    [Serializable]
    public class SecurityTokenArgumentException : ArgumentException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenException"/> class.
        /// </summary>
        public SecurityTokenArgumentException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public SecurityTokenArgumentException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The <see cref="Exception"/> that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public SecurityTokenArgumentException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenArgumentException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected SecurityTokenArgumentException(SerializationInfo info, StreamingContext context) : base(info, context) { }

        #region Experimental
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenArgumentNullException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="validationError">The <see cref="ValidationError"/> that is associated with the exception.</param>
        internal SecurityTokenArgumentException(string message, ValidationError validationError)
            : base(message)
        {
            ValidationError = validationError;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenArgumentException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="validationError">The <see cref="ValidationError"/> that is associated with the exception.</param>
        /// <param name="innerException">The <see cref="Exception"/> that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        internal SecurityTokenArgumentException(string message, ValidationError validationError, Exception innerException)
            : base(message, innerException)
        {
            ValidationError = validationError;
        }

        internal ValidationError ValidationError
        {
            get;
        }

        // TODO: add StackTrace when removing Experimental namespace as we can not make the StackTrace property internal.
        // public override string? StackTrace
        //{
        //    get
        //    {
        //        if (_stackTrace == null)
        //        {
        //            if (ValidationError == null)
        //                return base.StackTrace;
        //#if NET8_0_OR_GREATER
        //_stackTrace = new StackTrace(ValidationError.StackFrames).ToString();
        //#else
        //StringBuilder sb = new();
        //foreach (StackFrame frame in ValidationError.StackFrames)
        //{
        //    sb.Append(frame.ToString());
        //    sb.Append(Environment.NewLine);
        //}

        // _stackTrace = sb.ToString();
        //#endif
        //}

        //return _stackTrace;
        //}
        //}
        #endregion
    }
}
