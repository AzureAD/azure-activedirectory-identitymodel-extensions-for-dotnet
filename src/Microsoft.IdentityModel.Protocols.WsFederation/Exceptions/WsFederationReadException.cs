using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Exceptions
{
#if DESKTOPNET45
        [Serializable]
#endif
    /// <summary>
    /// This exception is thrown when processing Ws Federation metadata.
    /// </summary>
    public class WsFederationReadException : WsFederationException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        public WsFederationReadException()
            : base()
        { }

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

#if DESKTOPNET45
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationReadException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected WsFederationReadException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {}
#endif
    }
}
