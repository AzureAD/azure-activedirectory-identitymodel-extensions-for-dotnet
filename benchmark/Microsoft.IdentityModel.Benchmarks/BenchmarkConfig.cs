// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.Emit;

namespace Microsoft.IdentityModel.Benchmarks
{
    public class BenchmarkConfig : ManualConfig
    {
        public BenchmarkConfig()
        {
            AddJob(Job.MediumRun
                .WithToolchain(InProcessEmitToolchain.Instance))
            .AddColumn(StatisticColumn.P90, StatisticColumn.P95, StatisticColumn.P100);
        }
    }
}
