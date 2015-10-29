//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

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
        static IdentityModelEventSource()
        {
            Logger = new IdentityModelEventSource();
        }

        private IdentityModelEventSource()
        {
            LogLevel = EventLevel.Warning;
        }

        /// <summary>
        /// Static logger that is exposed externally. An external application or framework can hook up a listener to this event source to log data in a custom way.
        /// </summary>
        public static IdentityModelEventSource Logger { get; }

        [Event(6, Level = EventLevel.LogAlways)]
        public void WriteAlways(string message)
        {
            if (IsEnabled())
            {
                message = PrepareMessage(EventLevel.LogAlways, message);
                WriteEvent(6, message);
            }
        }

        [NonEvent]
        public void WriteAlways(string message, params object[] args)
        {
            if (IsEnabled())
            {
                if (args != null)
                    WriteAlways(string.Format(CultureInfo.InvariantCulture, message, args));
                else
                    WriteAlways(message);
            }
        }

        [Event(1, Level = EventLevel.Verbose)]
        public void WriteVerbose(string message)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Verbose)
            {
                message = PrepareMessage(EventLevel.Verbose, message);
                WriteEvent(1, message);
            }
        }

        [NonEvent]
        public void WriteVerbose(string message, params object[] args)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Verbose)
            {
                if (args != null)
                    WriteVerbose(string.Format(CultureInfo.InvariantCulture, message, args));
                else
                    WriteVerbose(message);
            }
        }

        [Event(2, Level = EventLevel.Informational)]
        public void WriteInformation(string message)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Informational)
            {
                message = PrepareMessage(EventLevel.Informational, message);
                WriteEvent(2, message);
            }
        }

        [NonEvent]
        public void WriteInformation(string message, params object[] args)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Informational)
            {
                if (args != null)
                    WriteInformation(string.Format(CultureInfo.InvariantCulture, message, args));
                else
                    WriteInformation(message);
            }
        }

        [Event(3, Level = EventLevel.Warning)]
        public void WriteWarning(string message)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Warning)
            {
                message = PrepareMessage(EventLevel.Warning, message);
                WriteEvent(3, message);
            }
        }

        [NonEvent]
        public void WriteWarning(string message, params object[] args)
        {
            if (args != null)
                WriteWarning(string.Format(CultureInfo.InvariantCulture, message, args));
            else
                WriteWarning(message);
        }

        [Event(4, Level = EventLevel.Error)]
        public void WriteError(string message)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Error)
            {
                message = PrepareMessage(EventLevel.Error, message);
                WriteEvent(4, message);
            }
        }

        [NonEvent]
        public void WriteError(string message, params object[] args)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Error)
            {
                if (args != null)
                    WriteError(string.Format(CultureInfo.InvariantCulture, message, args));
                else
                    WriteError(message);
            }
        }

        [Event(5, Level = EventLevel.Critical)]
        public void WriteCritical(string message)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Critical)
            {
                message = PrepareMessage(EventLevel.Critical, message);
                WriteEvent(5, message);
            }
        }

        [NonEvent]
        public void WriteCritical(string message, params object[] args)
        {
            if (IsEnabled() && LogLevel >= EventLevel.Critical)
            {
                if (args != null)
                    WriteCritical(string.Format(CultureInfo.InvariantCulture, message, args));
                else
                    WriteCritical(message);
            }
        }

        [NonEvent]
        public void Write(EventLevel level, Exception innerException, string message)
        {
            Write(level, innerException, message, null);
        }

        [NonEvent]
        public void Write(EventLevel level, Exception innerException, string message, params object[] args)
        {
            if (innerException != null)
            {
                message = string.Format(CultureInfo.InvariantCulture, "Message: {0}, InnerException: {1}", message, innerException.Message);
            }

            switch (level)
            {
                case EventLevel.LogAlways:
                    WriteAlways(message, args);
                    break;
                case EventLevel.Critical:
                    WriteCritical(message, args);
                    break;
                case EventLevel.Error:
                    WriteError(message, args);
                    break;
                case EventLevel.Warning:
                    WriteWarning(message, args);
                    break;
                case EventLevel.Informational:
                    WriteInformation(message, args);
                    break;
                case EventLevel.Verbose:
                    WriteVerbose(message, args);
                    break;
                default:
                    WriteError(string.Format(CultureInfo.InvariantCulture, LogMessages.MIML11002, level));
                    WriteError(message, args);
                    break;
            }
        }

        /// <summary>
        /// Minimum log level to log events. Default is Warning.
        /// </summary>
        public EventLevel LogLevel
        {
            get; set;
        }

        private string PrepareMessage(EventLevel level, string message, params object[] args)
        {
            if (message == null)
                return string.Empty;

            if (args != null)
                return string.Format(CultureInfo.InvariantCulture, "[{0}]{1} {2}", level.ToString(), DateTime.UtcNow.ToString(), 
                    string.Format(CultureInfo.InvariantCulture, message, args));

            return string.Format(CultureInfo.InvariantCulture, "[{0}]{1} {2}", level.ToString(), DateTime.UtcNow.ToString(), message);
        }
    }
}
