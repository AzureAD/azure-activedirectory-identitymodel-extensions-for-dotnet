// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Telemetry
{
    internal interface ITelemetryClient
    {
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            string configurationSource,
            TimeSpan operationDuration);

        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            string configurationSource,
            TimeSpan operationDuration,
            Exception exception);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            string configurationSource);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            string configurationSource,
            Exception exception);

        internal void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            string configurationSource,
            Exception exception);
    }
}
