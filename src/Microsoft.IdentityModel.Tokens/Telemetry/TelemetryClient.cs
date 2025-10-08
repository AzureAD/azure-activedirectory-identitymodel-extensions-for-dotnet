// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.ComponentModel;
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

        /// <summary>
        /// Extracts the domain name from a metadata address for telemetry purposes.
        /// Returns the full address if domain extraction fails or if the UseFullMetadataAddressForTelemetry switch is enabled.
        /// In error cases, always returns the full address for better debugging.
        /// </summary>
        /// <param name="metadataAddress">The full metadata address</param>
        /// <param name="isSuccessCase">True if this is a successful operation, false for error cases</param>
        /// <returns>Domain name for success cases (when switch is disabled), full address otherwise</returns>
        internal static string GetMetadataAddressForTelemetry(string metadataAddress, bool isSuccessCase = true)
        {
            // Always use full address for error cases or when the switch is enabled
            if (!isSuccessCase || AppContextSwitches.UseFullMetadataAddressForTelemetry || string.IsNullOrEmpty(metadataAddress))
                return metadataAddress;


            if (Uri.TryCreate(metadataAddress, UriKind.Absolute, out Uri result))
                return result.Host;

            return metadataAddress;
        }

        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource)
        {
            var tagList = new TagList()
            {
                { TelemetryConstants.IdentityModelVersionTag, ClientVer },
                { TelemetryConstants.MetadataAddressTag, GetMetadataAddressForTelemetry(metadataAddress, isSuccessCase: true) },
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
                { TelemetryConstants.MetadataAddressTag, GetMetadataAddressForTelemetry(metadataAddress, isSuccessCase: false) },
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
                { TelemetryConstants.MetadataAddressTag, GetMetadataAddressForTelemetry(metadataAddress, isSuccessCase: true) },
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
                { TelemetryConstants.MetadataAddressTag, GetMetadataAddressForTelemetry(metadataAddress, isSuccessCase: false) },
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
                { TelemetryConstants.MetadataAddressTag, GetMetadataAddressForTelemetry(metadataAddress, isSuccessCase: false) },
                { TelemetryConstants.ConfigurationSourceTag, configurationSource },
                { TelemetryConstants.ExceptionTypeTag, exception.GetType().ToString() },
                _blockingTagValue
            };

            TelemetryDataRecorder.IncrementBackgroundConfigurationRefreshFailureCounter(tagList);
        }

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, operationStatus, configurationSource) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus)
        {
            IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, TelemetryConstants.Protocols.ConfigurationSourceUnknown);
        }

        [Obsolete("Use IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public void IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, Exception exception)
        {
            IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, TelemetryConstants.Protocols.ConfigurationSourceUnknown, exception);
        }

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, configurationSource, operationDuration) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration)
        {
            LogConfigurationRetrievalDuration(metadataAddress, TelemetryConstants.Protocols.ConfigurationSourceUnknown, operationDuration);
        }

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, configurationSource, operationStatus, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public void LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration, Exception exception)
        {
            LogConfigurationRetrievalDuration(metadataAddress, TelemetryConstants.Protocols.ConfigurationSourceUnknown, operationDuration, exception);
        }

        [Obsolete("Use LogBackgroundConfigurationRefreshFailure(metadataAddress, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public void LogBackgroundConfigurationRefreshFailure(string metadataAddress, Exception exception)
        {
            LogBackgroundConfigurationRefreshFailure(metadataAddress, TelemetryConstants.Protocols.ConfigurationSourceUnknown, exception);
        }
    }
}
