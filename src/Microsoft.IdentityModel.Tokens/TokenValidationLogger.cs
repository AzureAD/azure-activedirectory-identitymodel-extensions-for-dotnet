// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER
using System;
#endif
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    internal static partial class TokenValidationLogger
    {
        private const string NonPiiFormat = "{0}";

        internal static ILogger GetLogger(this CallContext callContext) =>
            callContext?.Logger ?? NullLogger.Instance;

        internal static void AudienceValidated(this ILogger logger, string audience)
        {
            if (AppContextSwitches.SuccessValidationLogsAsInformation)
            {
                if (logger.IsEnabled(LogLevel.Information))
                    AudienceValidatedCore(logger, LogLevel.Information, FormatNonPii(audience));
            }
            else if (logger.IsEnabled(LogLevel.Debug))
            {
                AudienceValidatedCore(logger, LogLevel.Debug, FormatNonPii(audience));
            }
        }

        internal static void IssuerValidated(this ILogger logger, string issuer)
        {
            if (logger.IsEnabled(LogLevel.Information))
                IssuerValidatedCore(logger, FormatNonPii(issuer));
        }

        internal static void LifetimeValidated(this ILogger logger)
        {
            if (AppContextSwitches.SuccessValidationLogsAsInformation)
            {
                if (logger.IsEnabled(LogLevel.Information))
                    LifetimeValidatedCore(logger, LogLevel.Information);
            }
            else if (logger.IsEnabled(LogLevel.Debug))
            {
                LifetimeValidatedCore(logger, LogLevel.Debug);
            }
        }

        internal static void EmptyIssuerInValidIssuers(this ILogger logger)
        {
            if (logger.IsEnabled(LogLevel.Information))
                EmptyIssuerInValidIssuersCore(logger);
        }

        private static string FormatNonPii(object value) =>
            LogHelper.FormatInvariant(NonPiiFormat, LogHelper.MarkAsNonPII(value));

#if NET6_0_OR_GREATER
        [LoggerMessage(
            EventId = 10234,
            Message = "IDX10234: Audience Validated.Audience: '{Audience}'",
            SkipEnabledCheck = true)]
        private static partial void AudienceValidatedCore(ILogger logger, LogLevel level, string audience);

        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer Validated.Issuer: '{Issuer}'",
            SkipEnabledCheck = true)]
        private static partial void IssuerValidatedCore(ILogger logger, string issuer);

        [LoggerMessage(
            EventId = 10239,
            Message = "IDX10239: Lifetime of the token is valid.",
            SkipEnabledCheck = true)]
        private static partial void LifetimeValidatedCore(ILogger logger, LogLevel level);

        [LoggerMessage(
            EventId = 10262,
            Level = LogLevel.Information,
            Message = "IDX10262: One of the issuers in TokenValidationParameters.ValidIssuers was null or an empty string. See https://aka.ms/wilson/tokenvalidation for details.",
            SkipEnabledCheck = true)]
        private static partial void EmptyIssuerInValidIssuersCore(ILogger logger);
#else
        private static readonly Action<ILogger, string, Exception> s_audienceValidatedAsInformation =
            LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(10234, nameof(AudienceValidated)),
                "IDX10234: Audience Validated.Audience: '{Audience}'");

        private static readonly Action<ILogger, string, Exception> s_audienceValidatedAsDebug =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(10234, nameof(AudienceValidated)),
                "IDX10234: Audience Validated.Audience: '{Audience}'");

        private static readonly Action<ILogger, string, Exception> s_issuerValidated =
            LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(10236, nameof(IssuerValidated)),
                "IDX10236: Issuer Validated.Issuer: '{Issuer}'");

        private static readonly Action<ILogger, Exception> s_lifetimeValidatedAsInformation =
            LoggerMessage.Define(
                LogLevel.Information,
                new EventId(10239, nameof(LifetimeValidated)),
                "IDX10239: Lifetime of the token is valid.");

        private static readonly Action<ILogger, Exception> s_lifetimeValidatedAsDebug =
            LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(10239, nameof(LifetimeValidated)),
                "IDX10239: Lifetime of the token is valid.");

        private static readonly Action<ILogger, Exception> s_emptyIssuerInValidIssuers =
            LoggerMessage.Define(
                LogLevel.Information,
                new EventId(10262, nameof(EmptyIssuerInValidIssuers)),
                "IDX10262: One of the issuers in TokenValidationParameters.ValidIssuers was null or an empty string. See https://aka.ms/wilson/tokenvalidation for details.");

        private static void AudienceValidatedCore(ILogger logger, LogLevel level, string audience)
        {
            if (level == LogLevel.Information)
                s_audienceValidatedAsInformation(logger, audience, null);
            else
                s_audienceValidatedAsDebug(logger, audience, null);
        }

        private static void IssuerValidatedCore(ILogger logger, string issuer) =>
            s_issuerValidated(logger, issuer, null);

        private static void LifetimeValidatedCore(ILogger logger, LogLevel level)
        {
            if (level == LogLevel.Information)
                s_lifetimeValidatedAsInformation(logger, null);
            else
                s_lifetimeValidatedAsDebug(logger, null);
        }

        private static void EmptyIssuerInValidIssuersCore(ILogger logger) =>
            s_emptyIssuerInValidIssuers(logger, null);
#endif
    }
}
