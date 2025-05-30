// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Telemetry
{
    /// <summary>
    /// Prepares <see cref="TagList"/>s using the provided data and sends them to <see cref="TelemetryDataRecorder"/> for recording.
    /// </summary>
    internal class TelemetryClient : ITelemetryClient
    {
        public string ClientVer = IdentityModelTelemetryUtil.ClientVer;

        private KeyValuePair<string, object> _blockingTagValue = new(
            TelemetryConstants.BlockingTypeTag,
            AppContextSwitches.UpdateConfigAsBlocking.ToString()
        );

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            TelemetryDataRecorder.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, tagList);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            TelemetryDataRecorder.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, tagList);
        }

        public void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            string configurationSource,
            Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementBackgroundConfigurationRefreshFailureCounter(tagList);
        }
    }
}
