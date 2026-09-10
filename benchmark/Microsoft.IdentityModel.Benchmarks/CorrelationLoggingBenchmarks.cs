// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net9.0 --no-restore /p:NuGetAudit=false --filter Microsoft.IdentityModel.Benchmarks.CorrelationLoggingBenchmarks*
    //
    // Measures direct source-generated correlation logging for issue #3361.
    // The uncorrelated path does not include or format a correlation field. The correlated path
    // emits the explicitly supplied CorrelationId as part of the generated event.
    //
    // Uses the in-process toolchain so BenchmarkDotNet does not generate/restore a child project
    // (avoids offline NuGet audit failures).
    [Config(typeof(Config))]
    [MemoryDiagnoser]
    public partial class CorrelationLoggingBenchmarks
    {
        private sealed class Config : ManualConfig
        {
            public Config()
            {
                AddJob(Job.ShortRun.WithToolchain(InProcessEmitToolchain.Instance));
            }
        }

        private const string CorrelationId = "8fd7c1b2-3a4e-4c9d-9f2a-1b2c3d4e5f60";
        private const string Issuer = "https://login.microsoftonline.com/tenant-id/v2.0";

        private readonly ILogger _logger = new NullSinkLogger();
        private LoggerContext _correlatedContext;
        private LoggerContext _uncorrelatedContext;

        [GlobalSetup]
        public void Setup()
        {
            _uncorrelatedContext = new LoggerContext(_logger);
            _correlatedContext = new LoggerContext(_logger, CorrelationId);
        }

        [Benchmark(Baseline = true)]
        public void GeneratedMessage_NoCorrelation()
        {
            LogIssuerValidated(_uncorrelatedContext, Issuer);
        }

        [Benchmark]
        public void GeneratedMessage_WithCorrelation()
        {
            LogIssuerValidated(_correlatedContext, Issuer);
        }

        private static void LogIssuerValidated(LoggerContext loggerContext, string issuer)
        {
            if (loggerContext.LogCorrelationId && !string.IsNullOrEmpty(loggerContext.CorrelationId))
                LogIssuerValidatedWithCorrelation(loggerContext.Logger, issuer, loggerContext.CorrelationId);
            else
                LogIssuerValidated(loggerContext.Logger, issuer);
        }

        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer Validated.Issuer: '{issuer}'")]
        private static partial void LogIssuerValidated(ILogger logger, string issuer);

        [LoggerMessage(
            EventId = 10236,
            Level = LogLevel.Information,
            Message = "IDX10236: Issuer Validated.Issuer: '{issuer}', CorrelationId: '{correlationId}'")]
        private static partial void LogIssuerValidatedWithCorrelation(
            ILogger logger,
            string issuer,
            string correlationId);

        private sealed class NullSinkLogger : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                // Force the message to materialize (as a real sink would) without any extra sink-side cost.
                _ = formatter(state, exception);
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();
                public void Dispose() { }
            }
        }
    }

    // Measures the same correlation choices through a complete successful Experimental
    // JsonWebToken validation, including parsing, cryptography, and issuer validation.
    [Config(typeof(Config))]
    [MemoryDiagnoser]
    public class CorrelationLoggingEndToEndBenchmarks
    {
        private sealed class Config : ManualConfig
        {
            public Config()
            {
                AddJob(Job.ShortRun.WithToolchain(InProcessEmitToolchain.Instance));
            }
        }

        private const string CorrelationId = "8fd7c1b2-3a4e-4c9d-9f2a-1b2c3d4e5f60";

        private CallContext _legacyContext;
        private CallContext _loggerContext;
        private CallContext _correlatedLoggerContext;
        private JsonWebTokenHandler _handler;
        private IIdentityLogger _originalIdentityLogger;
        private string _token;
        private ValidationParameters _validationParameters;

        [GlobalSetup]
        public void Setup()
        {
            _handler = new JsonWebTokenHandler();
            _token = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            });

            _validationParameters = new ValidationParameters();
            _validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            _validationParameters.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);

            var logger = new NullSinkLogger();
            _legacyContext = new CallContext();
            _loggerContext = new CallContext(logger);
            _correlatedLoggerContext = new CallContext(logger, CorrelationId);

            _originalIdentityLogger = LogHelper.Logger;
            LogHelper.Logger = new LegacyNullSinkLogger();
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            LogHelper.Logger = _originalIdentityLogger;
        }

        [Benchmark(Baseline = true)]
        public async Task<bool> ValidateToken_LegacyIIdentityLogger()
        {
            ValidationResult<ValidatedToken, ValidationError> result =
                await _handler.ValidateTokenAsync(
                    _token,
                    _validationParameters,
                    _legacyContext,
                    default).ConfigureAwait(false);

            return result.Succeeded;
        }

        [Benchmark]
        public async Task<bool> ValidateToken_ILoggerWithoutCorrelation()
        {
            ValidationResult<ValidatedToken, ValidationError> result =
                await _handler.ValidateTokenAsync(
                    _token,
                    _validationParameters,
                    _loggerContext,
                    default).ConfigureAwait(false);

            return result.Succeeded;
        }

        [Benchmark]
        public async Task<bool> ValidateToken_ILoggerWithCorrelation()
        {
            ValidationResult<ValidatedToken, ValidationError> result =
                await _handler.ValidateTokenAsync(
                    _token,
                    _validationParameters,
                    _correlatedLoggerContext,
                    default).ConfigureAwait(false);

            return result.Succeeded;
        }

        private sealed class NullSinkLogger : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception exception,
                Func<TState, Exception, string> formatter)
            {
                _ = formatter(state, exception);
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();

                public void Dispose()
                {
                }
            }
        }

        private sealed class LegacyNullSinkLogger : IIdentityLogger
        {
            public bool IsEnabled(EventLogLevel eventLogLevel) => true;

            public void Log(LogEntry entry)
            {
                _ = entry.Message;
            }
        }
    }
}
