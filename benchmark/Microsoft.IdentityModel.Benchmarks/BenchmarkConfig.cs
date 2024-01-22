// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using Perfolizer.Horology;

namespace Microsoft.IdentityModel.Benchmarks
{
    public class BenchmarkConfig : ManualConfig
    {
        public BenchmarkConfig()
        {
            AddJob(Job.MediumRun
                .WithToolchain(InProcessEmitToolchain.Instance)
                .WithLaunchCount(4)
                .WithMaxAbsoluteError(TimeInterval.FromMilliseconds(10)))
                // uncomment to disable validation to enable debuging through benchmarks
                //.WithOption(ConfigOptions.DisableOptimizationsValidator, true)
                .AddColumn(StatisticColumn.P90, StatisticColumn.P95, StatisticColumn.P100);
        }
    }
}
