// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;


namespace Microsoft.IdentityModel.Benchmarks
{
        // Define custom columns for P50 and P99 latency
    public class P50Column : IColumn
    {
        public string Id => nameof(P50Column);
        public string ColumnName => "P50";
        public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase) => GetValue(summary, benchmarkCase, SummaryStyle.Default);
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style)
        {
            // Get the statistics for the current benchmark
            var statistics = summary[benchmarkCase].ResultStatistics;
            // Calculate the P50 latency using the Percentile method
            var p50 = statistics.Percentiles.P50 / style.TimeUnit.NanosecondAmount;
            // Format the value using the style
            return p50.ToString($"F2") + $" {style.TimeUnit.Name}";
        }
        public bool IsAvailable(Summary summary) => true;
        public bool AlwaysShow => true;
        public ColumnCategory Category => ColumnCategory.Statistics;
        public int PriorityInCategory => 0;
        public bool IsNumeric => true;
        public UnitType UnitType => UnitType.Time;
        public string Legend => "50th percentile of latency";
    }

    public class P95Column : IColumn
    {
        public string Id => nameof(P99Column);
        public string ColumnName => "P95";
        public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase) => GetValue(summary, benchmarkCase, SummaryStyle.Default);
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style)
        {
            // Get the statistics for the current benchmark
            var statistics = summary[benchmarkCase].ResultStatistics;
            // Calculate the P99 latency using the Percentile method
            var p95 = statistics.Percentiles.P95 / style.TimeUnit.NanosecondAmount;
            // Format the value using the style
            return p95.ToString($"F2") + $" {style.TimeUnit.Name}";
        }
        public bool IsAvailable(Summary summary) => true;
        public bool AlwaysShow => true;
        public ColumnCategory Category => ColumnCategory.Statistics;
        public int PriorityInCategory => 0;
        public bool IsNumeric => true;
        public UnitType UnitType => UnitType.Time;
        public string Legend => "95th percentile of latency";
    }

    public class P99Column : IColumn
    {
        public string Id => nameof(P99Column);
        public string ColumnName => "P99";
        public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase) => GetValue(summary, benchmarkCase, SummaryStyle.Default);
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style)
        {
            // Get the statistics for the current benchmark
            var statistics = summary[benchmarkCase].ResultStatistics;
            // Calculate the P99 latency using the Percentile method
            var p99 = statistics.Percentiles.P90 / style.TimeUnit.NanosecondAmount;
            // Format the value using the style
            return p99.ToString($"F2") + $" {style.TimeUnit.Name}";
        }
        public bool IsAvailable(Summary summary) => true;
        public bool AlwaysShow => true;
        public ColumnCategory Category => ColumnCategory.Statistics;
        public int PriorityInCategory => 0;
        public bool IsNumeric => true;
        public UnitType UnitType => UnitType.Time;
        public string Legend => "99th percentile of latency";
    }

    public class P100Column : IColumn
    {
        public string Id => nameof(P100Column);
        public string ColumnName => "P100";
        public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase) => GetValue(summary, benchmarkCase, SummaryStyle.Default);
        public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style)
        {
            // Get the statistics for the current benchmark
            var statistics = summary[benchmarkCase].ResultStatistics;
            // Calculate the P99 latency using the Percentile method
            var p100 = statistics.Percentiles.P100 / style.TimeUnit.NanosecondAmount;
            // Format the value using the style
            return p100.ToString($"F2")+ $" {style.TimeUnit.Name}";
        }
        public bool IsAvailable(Summary summary) => true;
        public bool AlwaysShow => true;
        public ColumnCategory Category => ColumnCategory.Statistics;
        public int PriorityInCategory => 0;
        public bool IsNumeric => true;
        public UnitType UnitType => UnitType.Time;
        public string Legend => "100th percentile of latency";
    }


    public class AntiVirusFriendlyConfig : ManualConfig
    {
        public AntiVirusFriendlyConfig()
        {
            AddJob(Job.MediumRun
                .WithToolchain(InProcessEmitToolchain.Instance));
            AddColumn(new P50Column(), new P95Column(), new P99Column(), new P100Column());
        }
    }
}
