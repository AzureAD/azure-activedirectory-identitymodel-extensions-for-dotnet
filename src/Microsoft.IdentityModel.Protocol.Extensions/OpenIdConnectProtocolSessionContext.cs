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
    /// A when an OpenIdConnectSession is established that context is storred here.
    /// see: http://openid.net/specs/openid-connect-session-1_0.html
    /// </summary>
    public class OpenIdConnectProtocolSessionContext
    {
        /// <summary>
        /// Creates an instance of <see cref="OpenIdConnectProtocolSessionContext"/>
        /// </summary>
        public OpenIdConnectProtocolSessionContext()
        {
        }

        /// <summary>
        /// Gets or sets the 'session_state' that is available when an 'OP' supports session management. 
        /// </summary>
        /// <remarks>see: http://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions </remarks>
        public string SessionState
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or set the 'check_session_iframe' url that is used to create java script to check when the 'session' has changed.
        /// </summary>
        /// <remarks>see: http://openid.net/specs/openid-connect-session-1_0.html#OPMetadata </remarks>
        public string CheckSessionIFrame
        {
            get;
            set;
        }
    }
}
