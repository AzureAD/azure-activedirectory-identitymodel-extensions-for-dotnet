// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Logging
{
    internal interface ITelemetryInstrumentation
    {
        internal void LogConfigurationRetrievalDuration(
            TimeSpan operationDuration);

        internal void LogConfigurationRetrievalDuration(
            TimeSpan operationDuration,
            Exception exception);

        internal void IncrementConfigurationRefreshRequestCounter(
            string operationStatus);

        internal void IncrementConfigurationRefreshRequestCounter(
            string operationStatus,
            Exception exception);
    }
}
