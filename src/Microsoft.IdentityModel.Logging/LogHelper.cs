using System;

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
        /// <param name="throwException">boolean to set whether to throw exception or not. Default is true.</param>
        public static void LogError(string message, Type exceptionType, bool throwException = true)
        {
            IdentityModelEventSource.Logger.WriteError(message);
            
            if (throwException)
            {
                throw (Exception)Activator.CreateInstance(exceptionType, message);
            }
        }
    }
}