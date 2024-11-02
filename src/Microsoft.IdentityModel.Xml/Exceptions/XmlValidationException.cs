// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Runtime.Serialization;
#pragma warning disable IDE0005 // Using directive is unnecessary.
using System.Text;
#pragma warning restore IDE0005 // Using directive is unnecessary.
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// This exception is thrown when a problem occurs when validating the XML &lt;Signature>.
    /// </summary>
    [Serializable]
    public class XmlValidationException : XmlException
    {
        [NonSerialized]
        private string _stackTrace;

        private ValidationError _validationError;

        /// <summary>
        /// Initializes a new instance of the <see cref="XmlValidationException"/> class.
        /// </summary>
        public XmlValidationException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="XmlValidationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public XmlValidationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="XmlValidationException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The <see cref="Exception"/> that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public XmlValidationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="XmlValidationException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected XmlValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        /// <summary>
        /// Sets the <see cref="ValidationError"/> that caused the exception.
        /// </summary>
        /// <param name="validationError"></param>
        internal void SetValidationError(ValidationError validationError)
        {
            _validationError = validationError;
        }

        /// <summary>
        /// Gets the stack trace that is captured when the exception is created.
        /// </summary>
        public override string StackTrace
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
