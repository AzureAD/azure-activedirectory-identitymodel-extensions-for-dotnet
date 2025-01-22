// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Telemetry.Tests
{
    public class MockTelemetryClient : ITelemetryClient
    {
        public Dictionary<string, object> ExportedItems = new Dictionary<string, object>();
        public Dictionary<string, object> ExportedHistogramItems = new Dictionary<string, object>();

        public void ClearExportedItems()
        {
            ExportedItems.Clear();
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus)
        {
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, Exception exception)
        {
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
            ExportedItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedHistogramItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration, Exception exception)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedHistogramItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedHistogramItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }
    }
}
