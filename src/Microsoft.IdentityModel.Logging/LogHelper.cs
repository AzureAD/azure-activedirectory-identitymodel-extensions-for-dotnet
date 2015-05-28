using System;
using System.Diagnostics.Tracing;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Helper class for logging.
    /// </summary>
    public class LogHelper
    {
        /// <summary>
        /// Logs an event using the event source logger and throws the exception.
        /// </summary>
        /// <param name="message">message to log.</param>
        /// <param name="exceptionType">Type of the exception to be thrown.</param>
        /// <param name="logLevel">Identifies the level of an event to be logged. Default is Error.</param>
        /// <param name="innerException">the inner <see cref="Exception"/> to be added to the outer exception.</param>
        public static void Throw(string message, Type exceptionType, EventLevel logLevel = EventLevel.Error, Exception innerException = null)
        {
            IdentityModelEventSource.Logger.Write(logLevel, message, innerException);

            if (innerException != null)
                throw (Exception)Activator.CreateInstance(exceptionType, message, innerException);
            else
                throw (Exception)Activator.CreateInstance(exceptionType, message);
        }
    }
}
