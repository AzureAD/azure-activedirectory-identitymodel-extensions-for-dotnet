// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Logging
{
    internal class TelemetryInstrumentation : ITelemetryInstrumentation
    {
        static TagList ClientVerTagList = new TagList()
        {
            { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer }
        };

        public void IncrementOperationCounter(string operationStatus)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, operationStatus }
            };

            IdentityModelTelemetry.IncrementOperationCounter(tagList);
        }

        public void IncrementOperationCounter(string operationStatus, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() }
            };

            IdentityModelTelemetry.IncrementOperationCounter(tagList);
        }

        public void LogOperationDuration(TimeSpan operationDuration)
        {
            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            IdentityModelTelemetry.RecordTotalDurationHistogram(durationInMilliseconds, ClientVerTagList);
        }

        public void LogOperationDuration(TimeSpan operationDuration, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() }
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            IdentityModelTelemetry.RecordTotalDurationHistogram(durationInMilliseconds, tagList);
        }
    }
}
