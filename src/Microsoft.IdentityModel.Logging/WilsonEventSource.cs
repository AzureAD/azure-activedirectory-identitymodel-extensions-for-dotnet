using System;
using System.Diagnostics.Tracing;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Event source based logger to log different events.
    /// </summary>
    public class WilsonEventSource : EventSource
    {
        private static EventLevel _logLevel;

        static WilsonEventSource()
		{
			Logger = new WilsonEventSource();
            _logLevel = EventLevel.Informational;
		}

        /// <summary>
        /// Static logger that is exposed externally. An external application or framework can hook up a listener to this event source to log data in a custom way.
        /// </summary>
        public static WilsonEventSource Logger { get; }

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

        /// <summary>
        /// Minimum log level to log events. Default is Informational.
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
