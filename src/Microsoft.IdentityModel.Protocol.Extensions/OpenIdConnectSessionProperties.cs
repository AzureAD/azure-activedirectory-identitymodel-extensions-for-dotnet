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
    /// Defines a set of properties names 
    /// </summary>
    public static class OpenIdConnectSessionProperties
    {
        /// <summary>
        /// Property defined for 'check_session_iframe'.
        /// </summary>
        public const string CheckSessionIFrame = ".checkSessionIFrame";
   
        /// <summary>
        /// Property defined for 'redirect_uri' set in the rquest for a 'code'
        /// </summary>
        public const string RedirectUri = ".redirect_uri";

        /// <summary>
        /// Property defined for 'session state'
        /// </summary>
        public const string SessionState = ".sessionState";

    }
}
