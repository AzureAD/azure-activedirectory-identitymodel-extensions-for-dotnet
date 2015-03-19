using System;
using System.Diagnostics;
using System.Diagnostics.Tracing;

namespace Microsoft.IdentityModel.Logging
{
    public class WilsonEventSource : EventSource
    {
        private static EventLevel _logLevel;

        static WilsonEventSource()
		{
			Logger = new WilsonEventSource();
            _logLevel = EventLevel.Informational;
		}

        private string GetCallerMethodName()
        {
#if DNX451
            var stackTrace = new StackTrace();
            var methodBase = stackTrace.GetFrame(2).GetMethod();
            var Class = methodBase.ReflectedType;
            var Namespace = Class.Namespace;         //Added finding the namespace
            return (Namespace + "." + Class.Name + "." + methodBase.Name);
#endif
            return "";
        }
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
