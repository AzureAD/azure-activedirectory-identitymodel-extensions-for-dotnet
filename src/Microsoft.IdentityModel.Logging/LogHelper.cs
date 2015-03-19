using System;

namespace Microsoft.IdentityModel.Logging
{
    public class LogHelper
    {
        public static void LogError(string message, Type exception, bool throwException = true)
        {
            WilsonEventSource.Logger.WriteError(message);
            
            if (throwException)
            {
                throw (Exception)Activator.CreateInstance(exception, message);
            }
        }
    }
}