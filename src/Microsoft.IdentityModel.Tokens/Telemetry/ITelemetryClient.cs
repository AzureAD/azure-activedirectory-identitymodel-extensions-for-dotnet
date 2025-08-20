// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ComponentModel;

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

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, operationStatus, configurationSource) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration);

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, configurationSource, operationStatus, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration,
            Exception exception);

        [Obsolete("Use IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, configurationSource) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus);

        [Obsolete("Use IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            Exception exception);

        [Obsolete("Use LogBackgroundConfigurationRefreshFailure(metadataAddress, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            Exception exception);


    }
}
