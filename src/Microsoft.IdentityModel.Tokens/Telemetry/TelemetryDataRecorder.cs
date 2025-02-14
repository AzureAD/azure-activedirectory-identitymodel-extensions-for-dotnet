// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Microsoft.IdentityModel.Telemetry
{
    /// <summary>
    /// Pushes telemetry data to the configured <see cref="Counter{T}"/> or <see cref="Histogram{T}"/>.
    /// </summary>
    internal class TelemetryDataRecorder
    {
        /// <summary>
        /// Meter name for MicrosoftIdentityModel.
        /// </summary>
        private const string MeterName = "MicrosoftIdentityModel_Meter";

        /// <summary>
        /// The meter responsible for creating instruments.
        /// </summary>
        private static readonly Meter IdentityModelMeter = new(MeterName, "1.0.0");

        internal const string TotalDurationHistogramName = "IdentityModelConfigurationRequestTotalDurationInMS";

        /// <summary>
        /// Counter to capture configuration refresh requests to ConfigurationManager.
        /// </summary>
        internal const string IdentityModelConfigurationManagerCounterName = "IdentityModelConfigurationManager";
        internal const string IdentityModelConfigurationManagerCounterDescription = "Counter capturing configuration manager operations.";
        internal static readonly Counter<long> ConfigurationManagerCounter = IdentityModelMeter.CreateCounter<long>(IdentityModelConfigurationManagerCounterName, description: IdentityModelConfigurationManagerCounterDescription);

        /// <summary>
        /// Histogram to capture total duration of configuration retrieval by ConfigurationManager in milliseconds.
        /// </summary>
        internal static readonly Histogram<long> TotalDurationHistogram = IdentityModelMeter.CreateHistogram<long>(
            TotalDurationHistogramName,
            unit: "ms",
            description: "Configuration retrieval latency during configuration manager operations.");

        internal static void RecordConfigurationRetrievalDurationHistogram(long requestDurationInMs, in TagList tagList)
        {
            TotalDurationHistogram.Record(requestDurationInMs, tagList);
        }

        internal static void IncrementConfigurationRefreshRequestCounter(in TagList tagList)
        {
            ConfigurationManagerCounter.Add(1, tagList);
        }
    }
}
