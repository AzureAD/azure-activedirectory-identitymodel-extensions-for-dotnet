// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Logging
{
    internal static class TelemetryConstants
    {
        // Static attribute tags
        public const string IdentityModelVersionTag = "IdentityModelVersion";
        public const string MetadataAddressTag = "MetadataAddress";
        public const string OperationStatusTag = "OperationStatus";
        public const string ExceptionTypeTag = "ExceptionType";

        public static class Protocols
        {
            // Configuration manager refresh statuses
            public const string Automatic = "Automatic";
            public const string Direct = "Direct";
            public const string FirstRefresh = "FirstRefresh";
            public const string LKG = "LastKnownGood";

            // Configuration manager exception types
            public const string ConfigurationInvalid = "ConfigurationInvalid";
            public const string ConfigurationRetrievalFailed = "ConfigurationRetrievalFailed";
        }
    }
}
