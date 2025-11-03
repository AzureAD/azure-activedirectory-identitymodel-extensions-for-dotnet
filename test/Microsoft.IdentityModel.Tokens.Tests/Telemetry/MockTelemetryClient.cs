// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Telemetry.Tests
{
    public class MockTelemetryClient : ITelemetryClient
    {
        public Dictionary<string, object> ExportedItems = new Dictionary<string, object>();
        public Dictionary<string, object> ExportedHistogramItems = new Dictionary<string, object>();

        internal int _requestRefreshCounter;

        public int RequestRefreshCounter => _requestRefreshCounter;

        public void ClearExportedItems()
        {
            ExportedItems.Clear();
            ExportedHistogramItems.Clear();
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource)
        {
            Interlocked.Increment(ref _requestRefreshCounter);
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
            ExportedItems.Add(TelemetryConstants.ConfigurationSourceTag, configurationSource);
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource, Exception exception)
        {
            Interlocked.Increment(ref _requestRefreshCounter);
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedItems.Add(TelemetryConstants.OperationStatusTag, operationStatus);
            ExportedItems.Add(TelemetryConstants.ConfigurationSourceTag, configurationSource);
            ExportedItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedHistogramItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedHistogramItems.Add(TelemetryConstants.ConfigurationSourceTag, configurationSource);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration, Exception exception)
        {
            ExportedHistogramItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedHistogramItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedHistogramItems.Add(TelemetryConstants.ConfigurationSourceTag, configurationSource);
            ExportedHistogramItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }

        void ITelemetryClient.LogBackgroundConfigurationRefreshFailure(string metadataAddress, string configurationSource, Exception exception)
        {
            ExportedItems.Add(TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer);
            ExportedItems.Add(TelemetryConstants.MetadataAddressTag, metadataAddress);
            ExportedItems.Add(TelemetryConstants.ConfigurationSourceTag, configurationSource);
            ExportedItems.Add(TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString());
        }

        void ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, Exception exception) => throw new NotImplementedException("This method shouldn't be called. It is kept only as back-compat mechanism in case of assembly version mismatch");
        void ITelemetryClient.LogBackgroundConfigurationRefreshFailure(string metadataAddress, Exception exception) => throw new NotImplementedException("This method shouldn't be called. It is kept only as back-compat mechanism in case of assembly version mismatch");
        void ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration) => throw new NotImplementedException("This method shouldn't be called. It is kept only as back-compat mechanism in case of assembly version mismatch");
        void ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration, Exception exception) => throw new NotImplementedException("This method shouldn't be called. It is kept only as back-compat mechanism in case of assembly version mismatch");
        void ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus) => throw new NotImplementedException("This method shouldn't be called. It is kept only as back-compat mechanism in case of assembly version mismatch");
    }
}
