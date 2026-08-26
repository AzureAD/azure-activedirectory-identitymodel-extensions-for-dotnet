// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER
using System;
#endif
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    internal static partial class XmlLogger
    {
        internal static void UnknownKeyInfoElementSkipped(this ILogger logger, string element)
        {
            if (logger.IsEnabled(LogLevel.Warning))
            {
                UnknownKeyInfoElementSkippedCore(
                    logger,
                    LogHelper.FormatInvariant("{0}", element));
            }
        }

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
