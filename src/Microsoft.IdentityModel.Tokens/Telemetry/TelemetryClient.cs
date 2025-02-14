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

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.OperationStatusTag, operationStatus },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementConfigurationRefreshRequestCounter(tagList);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                _blockingTagValue
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            TelemetryDataRecorder.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, tagList);
        }

        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration, Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            long durationInMilliseconds = (long)operationDuration.TotalMilliseconds;
            TelemetryDataRecorder.RecordConfigurationRetrievalDurationHistogram(durationInMilliseconds, tagList);
        }

        public void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            Exception exception)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, metadataAddress },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementBackgroundConfigurationRefreshFailureCounter(tagList);
        }
    }
}
