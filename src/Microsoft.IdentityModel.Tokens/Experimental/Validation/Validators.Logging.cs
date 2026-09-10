// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public static partial class Validators
    {
        private static void LogIssuerValidated(CallContext callContext, string issuer)
        {
            if (callContext?.Logger is not ILogger logger)
            {
                if (LogHelper.IsEnabled(EventLogLevel.Informational))
                    LogHelper.LogInformation(LogMessages.IDX10236, LogHelper.MarkAsNonPII(issuer));

                return;
            }

            if (IdentityModelEventSource.Logger.IsEnabled() &&
                IdentityModelEventSource.Logger.LogLevel >= System.Diagnostics.Tracing.EventLevel.Informational)
            {
                IdentityModelEventSource.Logger.WriteInformation(
                    LogMessages.IDX10236,
                    LogHelper.MarkAsNonPII(issuer));
            }

            if (callContext.LogCorrelationId && !string.IsNullOrEmpty(callContext.CorrelationId))
                LogIssuerValidatedWithCorrelationToILogger(logger, issuer, callContext.CorrelationId);
            else
                LogIssuerValidatedToILogger(logger, issuer);
        }

#if NET6_0_OR_GREATER
        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer Validated.Issuer: '{issuer}'")]
        private static partial void LogIssuerValidatedToILogger(ILogger logger, string issuer);

        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer Validated.Issuer: '{issuer}', CorrelationId: '{correlationId}'")]
        private static partial void LogIssuerValidatedWithCorrelationToILogger(
            ILogger logger,
            string issuer,
            string correlationId);
#else
        private static readonly System.Action<ILogger, string, System.Exception> s_logIssuerValidatedToILogger = LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(10236, nameof(LogIssuerValidatedToILogger)),
            "IDX10236: Issuer Validated.Issuer: '{issuer}'");

        private static void LogIssuerValidatedToILogger(ILogger logger, string issuer) =>
            s_logIssuerValidatedToILogger(logger, issuer, null);

        private static readonly System.Action<ILogger, string, string, System.Exception> s_logIssuerValidatedWithCorrelationToILogger =
            LoggerMessage.Define<string, string>(
                LogLevel.Information,
                new EventId(10236, nameof(LogIssuerValidatedWithCorrelationToILogger)),
                "IDX10236: Issuer Validated.Issuer: '{issuer}', CorrelationId: '{correlationId}'");

        private static void LogIssuerValidatedWithCorrelationToILogger(
            ILogger logger,
            string issuer,
            string correlationId) =>
            s_logIssuerValidatedWithCorrelationToILogger(logger, issuer, correlationId, null);
#endif
    }
}
