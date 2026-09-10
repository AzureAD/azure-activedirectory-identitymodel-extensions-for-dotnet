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
    // Measures the operation-level correlation scope introduced for issue #3361.
    // ActivityId is never converted for ILogger, and storing a CorrelationId on LoggerContext adds no
    // per-event formatting cost. Scope creation is paid once at the operation boundary.
    //
    // Reliable signal is Allocated. Key comparisons:
    //   Warning_CorrelationMetadataOnly vs Warning_NoCorrelation
    //   => supplying correlation metadata adds no cost to individual log events.
    //   OperationScope_CorrelationIdSet
    //   => measures the one-time scope cost for a single-event operation.
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

        [GlobalSetup]
        public void Setup()
        {
            // Default: nothing supplied. Mirrors the dominant production case.
            _noCorrelation = new LoggerContext(_logger);

            // Only ActivityId set (ETW). Post-fix this must NOT be promoted into the ILogger message.
            _activityIdOnly = new LoggerContext(_logger) { ActivityId = Guid.NewGuid() };

            // Explicitly supplied correlation string. It is consumed once by BeginCorrelationScope,
            // not formatted by each LogHelper call.
            _correlationIdSet = new LoggerContext(_logger) { CorrelationId = CorrelationId };
        }

        [Benchmark(Baseline = true)]
        public void Warning_NoCorrelation()
        {
            LogHelper.LogWarning(Message, _noCorrelation);
        }

        [Benchmark]
        public void Warning_ActivityIdOnly()
        {
            LogHelper.LogWarning(Message, _activityIdOnly);
        }

        [Benchmark]
        public void Warning_CorrelationMetadataOnly()
        {
            LogHelper.LogWarning(Message, _correlationIdSet);
        }

        [Benchmark]
        public void OperationScope_CorrelationIdSet()
        {
            using (_correlationIdSet.BeginCorrelationScope())
            {
                LogHelper.LogWarning(Message, _correlationIdSet);
            }
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
