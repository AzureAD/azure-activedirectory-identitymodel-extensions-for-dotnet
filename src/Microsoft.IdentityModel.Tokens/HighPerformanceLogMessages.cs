// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// [LoggerMessage] source generators require Microsoft.Extensions.Logging.Abstractions >= 6.0
// which is only available on net6.0+. Older TFMs (net462, net472, netstandard2.0) use MEL 2.1.0
// and fall back to the existing LogHelper methods.
#if NET6_0_OR_GREATER
using Microsoft.Extensions.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// High-performance logging methods using LoggerMessage source generators.
    /// These avoid allocations when the target log level is disabled.
    /// </summary>
    internal static partial class HighPerformanceLogMessages
    {
        // Success-path (hot): logged on every successful lifetime validation
        [LoggerMessage(
            EventId = 10239,
            Level = LogLevel.Information,
            Message = "IDX10239: Lifetime of the token is valid.")]
        internal static partial void LogLifetimeValidated(ILogger logger);

        // Same message at Debug level for non-SuccessValidationLogsAsInformation mode
        [LoggerMessage(
            EventId = 10240,
            Level = LogLevel.Debug,
            Message = "IDX10239: Lifetime of the token is valid.")]
        internal static partial void LogLifetimeValidatedVerbose(ILogger logger);

        // Warning: audience validation skipped
        [LoggerMessage(
            EventId = 10233,
            Level = LogLevel.Warning,
            Message = "IDX10233: ValidateAudience property on ValidationParameters is set to false. Exiting without validating the audience.")]
        internal static partial void LogAudienceValidationSkipped(ILogger logger);

        // Warning: issuer validation skipped
        [LoggerMessage(
            EventId = 10235,
            Level = LogLevel.Warning,
            Message = "IDX10235: ValidateIssuer property on ValidationParameters is set to false. Exiting without validating the issuer.")]
        internal static partial void LogIssuerValidationSkipped(ILogger logger);

        // Warning: lifetime validation skipped
        [LoggerMessage(
            EventId = 10238,
            Level = LogLevel.Warning,
            Message = "IDX10238: ValidateLifetime property on ValidationParameters is set to false. Exiting without validating the lifetime.")]
        internal static partial void LogLifetimeValidationSkipped(ILogger logger);

        // Warning: audience not required and empty
        [LoggerMessage(
            EventId = 10277,
            Level = LogLevel.Warning,
            Message = "IDX10277: RequireAudience property on ValidationParameters is set to false and no Audience was found. Exiting without validating the audience.")]
        internal static partial void LogAudienceNotRequired(ILogger logger);

        // Failure-adjacent: token not yet valid (uses pre-scrubbed values)
        [LoggerMessage(
            EventId = 10222,
            Level = LogLevel.Warning,
            Message = "IDX10222: Lifetime validation failed. The token is not yet valid. ValidFrom (UTC): '{NotBefore}', Current time (UTC): '{CurrentTime}'.")]
        internal static partial void LogTokenNotYetValid(ILogger logger, string notBefore, string currentTime);

        // Failure-adjacent: token expired
        [LoggerMessage(
            EventId = 10223,
            Level = LogLevel.Warning,
            Message = "IDX10223: Lifetime validation failed. The token is expired. ValidTo (UTC): '{Expires}', Current time (UTC): '{CurrentTime}'.")]
        internal static partial void LogTokenExpired(ILogger logger, string expires, string currentTime);

        // Info: issuer validated successfully
        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer validated. Issuer: '{Issuer}'.")]
        internal static partial void LogIssuerValidated(ILogger logger, string issuer);
    }
}
#endif
