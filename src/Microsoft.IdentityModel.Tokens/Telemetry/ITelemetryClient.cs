// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Telemetry
{
    internal interface ITelemetryClient
    {
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration);

        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration,
            Exception exception);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            Exception exception);
    }
}
