﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// This exception is thrown when processing Ws Federation metadata.
    /// </summary>
    [Serializable]
    public class WsFederationReadException : WsFederationException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        public WsFederationReadException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        public WsFederationReadException(string message)
            : base(message)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public WsFederationReadException(string message, Exception innerException)
            : base(message, innerException)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected WsFederationReadException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        { }
    }
}
