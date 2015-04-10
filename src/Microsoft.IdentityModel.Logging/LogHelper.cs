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
        /// Logs an error using the event source logger and throws an exception if the throwException is set to true.
        /// </summary>
        /// <param name="message">message to log.</param>
        /// <param name="exceptionType">Type of the exception to be thrown</param>
        /// <param name="exception">Exception parameter to be passed to the exception thrown.</param>
        /// <param name="throwException">boolean to set whether to throw exception or not. Default is true.</param>
        public static void Throw(string message, Type exceptionType, EventLevel logLevel, Exception exception = null, bool throwException = true)
        {
            if (logLevel == EventLevel.Error)
            {
                IdentityModelEventSource.Logger.WriteError(message);
            }
            else if (logLevel == EventLevel.Verbose)
            {
                IdentityModelEventSource.Logger.WriteVerbose(message);
            }

            if (throwException)
            {
                if (exception != null)
                {
                    throw (Exception)Activator.CreateInstance(exceptionType, message, exception);
                }
                else
                {
                    throw (Exception)Activator.CreateInstance(exceptionType, message);
                }
            }
        }
    }
}