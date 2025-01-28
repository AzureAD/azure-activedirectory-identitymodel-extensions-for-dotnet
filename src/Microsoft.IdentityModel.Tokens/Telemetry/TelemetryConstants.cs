// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Telemetry
{
    internal static class TelemetryConstants
    {
        // Static attribute tags

        /// <summary>
        /// Telemetry tag indicating the version of the IdentityModel library.
        /// </summary>
        public const string IdentityModelVersionTag = "IdentityModelVersion";

        /// <summary>
        /// Telemetry tag indicating the endpoint from which a configuration is retrieved.
        /// </summary>
        public const string MetadataAddressTag = "MetadataAddress";

        /// <summary>
        /// Telemetry tag describing the operation being performed.
        /// </summary>
        public const string OperationStatusTag = "OperationStatus";

        /// <summary>
        /// Telemetry tag indicating the type of exception that occurred.
        /// </summary>
        public const string ExceptionTypeTag = "ExceptionType";

        public static class Protocols
        {
            // Configuration manager refresh statuses

            /// <summary>
            /// Telemetry tag indicating configuration retrieval after the refresh interval has expired.
            /// </summary>
            public const string Automatic = "Automatic";

            /// <summary>
            /// Telemetry tag indicating configuration retrieval per a call to RequestRefresh.
            /// </summary>
            public const string Manual = "Manual";

            /// <summary>
            /// Telemetry tag indicating configuration retrieval when there is no previously cached configuration.
            /// </summary>
            public const string FirstRefresh = "FirstRefresh";

            /// <summary>
            /// Telemetry tag indicating configuration retrieval when the last known good configuration is needed.
            /// </summary>
            public const string Lkg = "LastKnownGood";

            // Configuration manager exception types

            /// <summary>
            /// Telemetry tag indicating that configuration could not be sucessfully validated after retrieval.
            /// </summary>
            public const string ConfigurationInvalid = "ConfigurationInvalid";

            /// <summary>
            /// Telemetry tag indicating that configuration could not be retrieved successfully.
            /// </summary>
            public const string ConfigurationRetrievalFailed = "ConfigurationRetrievalFailed";
        }
    }
}
