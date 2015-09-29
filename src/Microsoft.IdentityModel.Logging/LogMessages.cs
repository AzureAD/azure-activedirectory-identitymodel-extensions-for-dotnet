//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Log messages and codes for Microsoft.IdentityModel.Logging
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        internal const string MIML10000 = "MIML10000: The parameter '{0}' cannot be a 'null' or an empty object.";
        internal const string MIML10001 = "MIML10001: The property value '{0}' cannot be a 'null' or an empty object.";

        // logging
        internal const string MIML11000 = "MIML11000: eventData.Payload is null or empty. Not logging any messages.";
        internal const string MIML11001 = "MIML11001: Cannot create the fileStream or StreamWriter to write logs. Exception: {0}";
#pragma warning restore 1591

    }
}
