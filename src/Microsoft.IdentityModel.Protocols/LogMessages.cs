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

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        internal const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty object.";
        internal const string IDX10001 = "IDX10001: The property value '{0}' cannot be a 'null' or an empty object.";
        internal const string IDX10002 = "IDX10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.";

        // properties, configuration 
        internal const string IDX10106 = "IDX10106: When setting RefreshInterval, the value must be greater than MinimumRefreshInterval: '{0}'. value: '{1}'";
        internal const string IDX10107 = "IDX10107: When setting AutomaticRefreshInterval, the value must be greater than MinimumAutomaticRefreshInterval: '{0}'. value: '{1}'";
        internal const string IDX10108 = "IDX10108: The address specified is not valid as per HTTPS scheme. Please specify an https address for security reasons. If you want to test with http address, set the RequireHttps property  on IDocumentRetriever to false. address: '{0}'";

        // configuration retrieval errors
        internal const string IDX10803 = "IDX10803: Unable to obtain configuration from: '{0}'. Inner Exception: '{1}'.";
        internal const string IDX10804 = "IDX10804: Unable to retrieve document from: '{0}'.";
        internal const string IDX10805 = "IDX10805: Obtaining information from metadata endpoint: '{0}'";
        internal const string IDX10814 = "IDX10814: Cannot read file from the address: '{0}'. File does not exist.";
#pragma warning restore 1591


    }
}