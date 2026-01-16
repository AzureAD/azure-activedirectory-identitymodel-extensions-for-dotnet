// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ComponentModel;

namespace Microsoft.IdentityModel.Telemetry
{
    internal interface ITelemetryClient
    {
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            string configurationSource,
            TimeSpan operationDuration);

        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            string configurationSource,
            TimeSpan operationDuration,
            Exception exception);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            string configurationSource);

        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            string configurationSource,
            Exception exception);

        internal void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            string configurationSource,
            Exception exception);

        /// <summary>
        /// Increments the signature validation counter with algorithm and key size details.
        /// </summary>
        /// <param name="isSuccess">Whether the signature validation succeeded.</param>
        /// <param name="algorithm">The signature algorithm used (e.g., RS256, ES256, HS256).</param>
        /// <param name="keySize">The size of the key in bits (e.g., 2048, 3072, 4096).</param>
        internal void IncrementSignatureValidationCounter(bool isSuccess, string algorithm, int keySize);

        /// <summary>
        /// Increments the token decryption counter with encryption algorithm, scheme, and key size details.
        /// </summary>
        /// <param name="isSuccess">Whether the token decryption succeeded.</param>
        /// <param name="encryptionAlgorithm">The key encryption algorithm used (e.g., RSA-OAEP, A256KW).</param>
        /// <param name="encryptionScheme">The content encryption scheme used (e.g., A256GCM, A128CBC-HS256).</param>
        /// <param name="keySize">The size of the key encryption key in bits (e.g., 2048, 3072, 4096 for RSA, 128, 256 for AES).</param>
        internal void IncrementTokenDecryptionCounter(bool isSuccess, string encryptionAlgorithm, string encryptionScheme, int keySize);

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, operationStatus, configurationSource) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration);

        [Obsolete("Use LogConfigurationRetrievalDuration(metadataAddress, configurationSource, operationStatus, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogConfigurationRetrievalDuration(
            string metadataAddress,
            TimeSpan operationDuration,
            Exception exception);

        [Obsolete("Use IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, configurationSource) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus);

        [Obsolete("Use IncrementConfigurationRefreshRequestCounter(metadataAddress, operationStatus, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void IncrementConfigurationRefreshRequestCounter(
            string metadataAddress,
            string operationStatus,
            Exception exception);

        [Obsolete("Use LogBackgroundConfigurationRefreshFailure(metadataAddress, configurationSource, exception) instead.", false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void LogBackgroundConfigurationRefreshFailure(
            string metadataAddress,
            Exception exception);


    }
}
