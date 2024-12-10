// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Logging
{
    internal class TelemetryInstrumentation : ITelemetryInstrumentation
    {
        static TagList ClientVerTagList = new()
        {
            { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer }
        };

        public void IncrementConfigurationRefreshRequestCounter(string operationStatus)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, operationStatus }
            };

            IdentityModelTelemetry.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void IncrementConfigurationRefreshRequestCounter(string operationStatus, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() }
            };

            IdentityModelTelemetry.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void LogConfigurationRetrievalDuration(TimeSpan operationDuration)
        {
            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            IdentityModelTelemetry.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, ClientVerTagList);
        }

        public void LogConfigurationRetrievalDuration(TimeSpan operationDuration, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() }
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            IdentityModelTelemetry.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, tagList);
        }
    }
}
