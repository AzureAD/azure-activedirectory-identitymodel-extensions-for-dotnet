// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER
using System;
#endif
using Microsoft.Extensions.Logging;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// High-performance logging methods for XML operations.
    /// </summary>
    public static partial class LoggerExtensions
    {
        /// <summary>
        /// Logs that an unknown child element in a KeyInfo element was skipped.
        /// </summary>
        /// <param name="logger">The logger used to write the message.</param>
        /// <param name="element">The skipped XML element.</param>
        [System.CLSCompliant(false)]
        public static void UnknownKeyInfoElementSkipped(this ILogger logger, string element) =>
            UnknownKeyInfoElementSkippedCore(logger, element);

#if NET6_0_OR_GREATER
        [LoggerMessage(
            EventId = 30300,
            Level = LogLevel.Warning,
            Message = "IDX30300: KeyInfo skipped unknown element: '{Element}'.")]
        private static partial void UnknownKeyInfoElementSkippedCore(ILogger logger, string element);
#else
        private static readonly Action<ILogger, string, Exception> s_unknownKeyInfoElementSkipped =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(30300, nameof(UnknownKeyInfoElementSkipped)),
                "IDX30300: KeyInfo skipped unknown element: '{Element}'.");

        private static void UnknownKeyInfoElementSkippedCore(ILogger logger, string element) =>
            s_unknownKeyInfoElementSkipped(logger, element, null);
#endif
    }
}
