// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Logging
{
    internal interface ITelemetryInstrumentation
    {
        internal void LogOperationDuration(
            TimeSpan operationDuration);

        internal void LogOperationDuration(
            TimeSpan operationDuration,
            Exception exception);

        internal void IncrementOperationCounter(
            string operationStatus);

        internal void IncrementOperationCounter(
            string operationStatus,
            Exception exception);
    }
}
