// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    [Serializable]
    /// <summary>
    /// This exception is thrown when an OpenIdConnect protocol handler encounters a protocol error.
    /// </summary>
    public class OpenIdConnectProtocolException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectProtocolException"/> class.
        /// </summary>
        public OpenIdConnectProtocolException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectProtocolException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        public OpenIdConnectProtocolException(String message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectProtocolException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public OpenIdConnectProtocolException(String message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectProtocolException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected OpenIdConnectProtocolException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}