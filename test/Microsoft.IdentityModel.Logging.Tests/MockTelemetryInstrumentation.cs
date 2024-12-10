// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class MockTelemetryInstrumentation : ITelemetryInstrumentation
    {
        public Dictionary<string, object> ExportedItems = new Dictionary<string, object>();
        public Dictionary<string, object> ExportedHistogramItems = new Dictionary<string, object>();

        public void ClearExportedItems()
        {
            ExportedItems.Clear();
        }

        public void IncrementConfigurationRefreshRequestCounter(string operationStatus)
        {
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
        }

        public void IncrementConfigurationRefreshRequestCounter(string operationStatus, Exception exception)
        {
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
            ExportedItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }

        public void LogConfigurationRetrievalDuration(TimeSpan operationDuration)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
        }

        public void LogConfigurationRetrievalDuration(TimeSpan operationDuration, Exception exception)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedHistogramItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }
    }
}
