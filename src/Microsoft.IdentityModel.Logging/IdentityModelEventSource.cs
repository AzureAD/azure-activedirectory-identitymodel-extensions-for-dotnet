using System;
using System.Diagnostics.Tracing;
using System.Globalization;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Event source based logger to log different events.
    /// </summary>
    public class IdentityModelEventSource : EventSource
    {
        private static EventLevel _logLevel;

        static IdentityModelEventSource()
        {
            Logger = new IdentityModelEventSource();
            _logLevel = EventLevel.Warning;
        }

        /// <summary>
        /// Static logger that is exposed externally. An external application or framework can hook up a listener to this event source to log data in a custom way.
        /// </summary>
        public static IdentityModelEventSource Logger { get; }

        [Event(1, Level = EventLevel.Verbose)]
        public void WriteVerbose(string message)
        {
            if (_logLevel >= EventLevel.Verbose)
            {
                WriteEvent(1, message);
            }
        }

        [Event(2, Level = EventLevel.Informational)]
        public void WriteInformation(string message)
        {
            if (_logLevel >= EventLevel.Informational)
            {
                WriteEvent(2, message);
            }
        }

        [Event(3, Level = EventLevel.Warning)]
        public void WriteWarning(string message)
        {
            if (_logLevel >= EventLevel.Warning)
            {
                WriteEvent(3, message);
            }
        }

        [Event(4, Level = EventLevel.Error)]
        public void WriteError(string message)
        {
            if (_logLevel >= EventLevel.Error)
            {
                WriteEvent(4, message);
            }
        }

        [Event(5, Level = EventLevel.Critical)]
        public void WriteCritical(string message)
        {
            if (_logLevel >= EventLevel.Error)
            {
                WriteEvent(5, message);
            }
        }

        [NonEvent]
        public void Write(EventLevel level, string message, Exception innerException)
        {
            if (innerException != null)
            {
                message = String.Format(CultureInfo.InvariantCulture, "Message: {0}, InnerException: {1}", message, innerException.ToString());
            }

            switch (level)
            {
                case EventLevel.Critical:
                    WriteCritical(message);
                    break;
                case EventLevel.Error:
                    WriteError(message);
                    break;
                case EventLevel.Warning:
                    WriteWarning(message);
                    break;
                case EventLevel.Informational:
                    WriteInformation(message);
                    break;
                case EventLevel.Verbose:
                    WriteVerbose(message);
                    break;
                default:
                    LogHelper.Throw("Unknown log level.", typeof(ArgumentException), EventLevel.Error);
                    break;
            }
        }

        /// <summary>
        /// Minimum log level to log events. Default is Warning.
        /// </summary>
        public static EventLevel LogLevel
        {
            get
            {
                return _logLevel;
            }
            set
            {
                _logLevel = value;
            }
        }
    }
}
