// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// This exception is thrown when retrieved configuration is not valid.
    /// </summary>
    [Serializable]
    public class ConfigurationInvalidException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationInvalidException"/> class.
        /// </summary>
        public ConfigurationInvalidException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationInvalidException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        public ConfigurationInvalidException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationInvalidException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public ConfigurationInvalidException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationInvalidException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected ConfigurationInvalidException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
