//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Diagnostics.Tracing;
using System.Globalization;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Event source based logger to log different events.
    /// </summary>
    [EventSource(Name = "Microsoft.IdentityModel.EventSource")]
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
            if (IsEnabled() && _logLevel >= EventLevel.Verbose)
            {
                message = PrepareMessage(message, EventLevel.Verbose);
                WriteEvent(1, message);
            }
        }

        [Event(2, Level = EventLevel.Informational)]
        public void WriteInformation(string message)
        {
            if (IsEnabled() && _logLevel >= EventLevel.Informational)
            {
                message = PrepareMessage(message, EventLevel.Informational);
                WriteEvent(2, message);
            }
        }

        [Event(3, Level = EventLevel.Warning)]
        public void WriteWarning(string message)
        {
            if (IsEnabled() && _logLevel >= EventLevel.Warning)
            {
                message = PrepareMessage(message, EventLevel.Warning);
                WriteEvent(3, message);
            }
        }

        [Event(4, Level = EventLevel.Error)]
        public void WriteError(string message)
        {
            if (IsEnabled() && _logLevel >= EventLevel.Error)
            {
                message = PrepareMessage(message, EventLevel.Error);
                WriteEvent(4, message);
            }
        }

        [Event(5, Level = EventLevel.Critical)]
        public void WriteCritical(string message)
        {
            if (IsEnabled() && _logLevel >= EventLevel.Critical)
            {
                message = PrepareMessage(message, EventLevel.Critical);
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
                    WriteError(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML11002, level.ToString()));
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

        private string PrepareMessage(string message, EventLevel level)
        {
            if (message == null)
            {
                return message;
            }

            return string.Format(CultureInfo.InvariantCulture, "[{0}]{1} {2}", level.ToString(), DateTime.UtcNow.ToString(), message);
        }
    }
}
