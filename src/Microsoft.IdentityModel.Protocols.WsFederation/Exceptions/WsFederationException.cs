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
    /// Represents a Ws Federation exception.
    /// </summary>
    public class WsFederationException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationException"/> class.
        /// </summary>
        public WsFederationException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public WsFederationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The <see cref="Exception"/> that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public WsFederationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if DESKTOPNET45
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected WsFederationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif

    }
}
