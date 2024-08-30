// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// This exception is thrown when specific cloud instance was not matched with cloud instance of signing key.
    /// </summary>
    [Serializable]
    public class SecurityTokenInvalidCloudInstanceException : SecurityTokenValidationException
    {
        [NonSerialized]
        const string _Prefix = "Microsoft.IdentityModel." + nameof(SecurityTokenInvalidCloudInstanceException) + ".";

        [NonSerialized]
        const string _InvalidCloudInstanceKey = _Prefix + nameof(InvalidCloudInstance);

        /// <summary>
        /// Gets or sets the invalid cloud instance that created the validation exception.
        /// </summary>
        public string InvalidCloudInstance { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenInvalidCloudInstanceException"/> class.
        /// </summary>
        public SecurityTokenInvalidCloudInstanceException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenInvalidCloudInstanceException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        public SecurityTokenInvalidCloudInstanceException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenInvalidCloudInstanceException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public SecurityTokenInvalidCloudInstanceException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenInvalidCloudInstanceException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
#if NET8_0_OR_GREATER
        [Obsolete("Formatter-based serialization is obsolete", DiagnosticId = "SYSLIB0051")]
#endif
        protected SecurityTokenInvalidCloudInstanceException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            SerializationInfoEnumerator enumerator = info.GetEnumerator();
            while (enumerator.MoveNext())
            {
                switch (enumerator.Name)
                {
                    case _InvalidCloudInstanceKey:
                        InvalidCloudInstance = info.GetString(_InvalidCloudInstanceKey);
                        break;

                    default:
                        // Ignore other fields.
                        break;
                }
            }
        }

        /// <inheritdoc/>
#if NET8_0_OR_GREATER
        [Obsolete("Formatter-based serialization is obsolete", DiagnosticId = "SYSLIB0051")]
#endif
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);

            if (!string.IsNullOrEmpty(InvalidCloudInstance))
                info.AddValue(_InvalidCloudInstanceKey, InvalidCloudInstance);
        }
    }
}
