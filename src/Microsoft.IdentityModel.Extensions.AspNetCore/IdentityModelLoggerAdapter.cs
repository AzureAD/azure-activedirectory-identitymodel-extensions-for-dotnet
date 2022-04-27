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

#if NETSTANDARD2_0

using System;
using System.Diagnostics.Tracing;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Abstractions;

namespace Microsoft.IdentityModel.Extensions.AspNetCore
{
    /// <summary>
    /// The default implementation of <see cref="IIdentityLogger"/> that provides a wrapper around <see cref="ILogger"/> instance.
    /// </summary>
    public class IdentityModelLoggerAdapter : IIdentityLogger
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Instantiates <see cref="IdentityModelLoggerAdapter"/> using <paramref name="logger"/>
        /// </summary>
        /// <param name="logger"></param>

#pragma warning disable CS3001 // Argument type is not CLS-compliant
        public IdentityModelLoggerAdapter(ILogger logger)
#pragma warning restore CS3001 // Argument type is not CLS-compliant
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public bool IsEnabled(EventLevel eventLevel)
        {
            return _logger.IsEnabled(ConvertToLogLevel(eventLevel));
        }

        /// <inheritdoc/>
        public void Log(LogEntry entry)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));

            string message = FormatEntry(entry);

            switch (entry.EventLevel)
            {
                case EventLevel.LogAlways:
                    _logger.LogTrace(message);
                    break;

                case EventLevel.Critical:
                    _logger.LogCritical(message);
                    break;

                case EventLevel.Error:
                    _logger.LogError(message);
                    break;

                case EventLevel.Warning:
                    _logger.LogWarning(message);
                    break;

                case EventLevel.Informational:
                    _logger.LogInformation(message);
                    break;

                case EventLevel.Verbose:
                    _logger.LogDebug(message);
                    break;

                default:
                    break;
            }
        }

        private static string FormatEntry(LogEntry entry)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(entry.CorrelationId).Append(";");
            sb.Append(entry.Message);
            return sb.ToString();
        }

        private static LogLevel ConvertToLogLevel(EventLevel eventLevel)
        {
            switch (eventLevel)
            {
                case EventLevel.LogAlways:
                    return LogLevel.Trace;

                case EventLevel.Critical:
                    return LogLevel.Critical;

                case EventLevel.Error:
                    return LogLevel.Error;

                case EventLevel.Warning:
                    return LogLevel.Warning;

                case EventLevel.Informational:
                    return LogLevel.Information;

                case EventLevel.Verbose:
                default:
                    return LogLevel.Debug;
            }
        }
    }
}
#endif
