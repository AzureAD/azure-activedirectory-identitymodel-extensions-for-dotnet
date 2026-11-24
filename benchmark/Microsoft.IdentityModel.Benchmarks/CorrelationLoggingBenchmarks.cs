// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net9.0 --no-restore /p:NuGetAudit=false --filter Microsoft.IdentityModel.Benchmarks.CorrelationLoggingBenchmarks*
    //
    // Isolates the correlation-id resolution cost on the ILogger warning path in LogHelper.
    // Validates the engine change for issue #3361: the ActivityId->string fallback was removed and
    // correlation logging is gated by LoggerContext.LogCorrelationId (default true, kill switch).
    //
    // Reliable signal is Allocated. Key comparisons:
    //   New_Warning_ActivityIdOnly (real, fixed path)  vs  Old_Warning_ActivityIdOnly_Simulated (pre-fix cost)
    //   => the delta is the per-log Guid->string + correlation string.Format the fix eliminates.
    //
    // Uses the in-process toolchain so BenchmarkDotNet does not generate/restore a child project
    // (avoids offline NuGet audit failures).
    [Config(typeof(Config))]
    [MemoryDiagnoser]
    public class CorrelationLoggingBenchmarks
    {
        private sealed class Config : ManualConfig
        {
            public Config()
            {
                AddJob(Job.ShortRun.WithToolchain(InProcessEmitToolchain.Instance));
            }
        }

        private const string Message = "IDX10233: ValidateAudience property on ValidationParameters is set to false. Exiting without validating the audience.";
        private const string CorrelationId = "8fd7c1b2-3a4e-4c9d-9f2a-1b2c3d4e5f60";

        private readonly ILogger _logger = new NullSinkLogger();

        private LoggerContext _noCorrelation;
        private LoggerContext _activityIdOnly;
        private LoggerContext _correlationIdSet;
        private LoggerContext _killSwitchOff;

        [GlobalSetup]
        public void Setup()
        {
            // Default: nothing supplied. Mirrors the dominant production case.
            _noCorrelation = new LoggerContext(_logger);

            // Only ActivityId set (ETW). Post-fix this must NOT be promoted into the ILogger message.
            _activityIdOnly = new LoggerContext(_logger) { ActivityId = Guid.NewGuid() };

            // Explicitly supplied correlation string (the supported opt-in path).
            _correlationIdSet = new LoggerContext(_logger) { CorrelationId = CorrelationId };

            // Kill switch: correlation supplied but LogCorrelationId disabled -> nothing appended.
            _killSwitchOff = new LoggerContext(_logger) { CorrelationId = CorrelationId, LogCorrelationId = false };
        }

        // --- Real (fixed) LogHelper paths ---

        [Benchmark(Baseline = true)]
        public void New_Warning_NoCorrelation()
        {
            LogHelper.LogWarning(Message, _noCorrelation);
        }

        [Benchmark]
        public void New_Warning_ActivityIdOnly()
        {
            LogHelper.LogWarning(Message, _activityIdOnly);
        }

        [Benchmark]
        public void New_Warning_CorrelationIdSet()
        {
            LogHelper.LogWarning(Message, _correlationIdSet);
        }

        [Benchmark]
        public void New_Warning_KillSwitchOff()
        {
            LogHelper.LogWarning(Message, _killSwitchOff);
        }

        // --- Control: reproduces the pre-fix ActivityId->string fallback cost per log ---

        [Benchmark]
        public void Old_Warning_ActivityIdOnly_Simulated()
        {
            // The removed behavior materialized ActivityId as a string and fed it as the correlation id,
            // forcing a Guid->string allocation plus the correlation string.Format in WriteEntry on every log.
            var ctx = new LoggerContext(_logger) { ActivityId = _activityIdOnly.ActivityId };
            ctx.CorrelationId = ctx.ActivityId.ToString();
            LogHelper.LogWarning(Message, ctx);
        }

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
}
