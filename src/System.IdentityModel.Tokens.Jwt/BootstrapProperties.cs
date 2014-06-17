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

using System.Collections.Generic;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a set of properties that were obtained when a user authenticates
    /// </summary>
    public class BootstrapProperties
    {
        private Dictionary<string, string> _properties = new Dictionary<string, string>();

        /// <summary>
        /// Property defined for 'check_session_iframe'.
        /// </summary>
        public const string CheckSessionIFrameProperty = ".checkSessionIFrame";

        /// <summary>
        /// Property defined for 'security token'
        /// </summary>
        public const string SecurityTokenProperty = ".securityToken";

        /// <summary>
        /// Property defined for 'session state'
        /// </summary>
        public const string SessionStateProperty = ".sessionState";

        
        /// <summary>
        /// Creates a new instance of <see cref="BootstrapProperties"/>.
        /// </summary>
        public BootstrapProperties()
        {
        }

        /// <summary>
        /// Gets the properties.
        /// </summary>
        public IDictionary<string, string> Properties
        {
            get
            {
                return _properties;
            }
        }

        /// <summary>
        /// Gets or sets the CheckSessionIFrame
        /// </summary>
        public string CheckSessionIFrame
        {
            get
            {
                string value;
                return _properties.TryGetValue(CheckSessionIFrameProperty, out value) ? value : null;
            }
            set
            {
                if (_properties.ContainsKey(CheckSessionIFrameProperty))
                {
                    _properties.Remove(CheckSessionIFrameProperty);
                }

                _properties[CheckSessionIFrameProperty] = value;
            }
        }

        /// <summary>
        /// Gets or sets the SecurityToken
        /// </summary>
        public string SecurityToken
        {
            get
            {
                string value;
                return _properties.TryGetValue(SecurityTokenProperty, out value) ? value : null;
            }
            set
            {
                if (_properties.ContainsKey(SecurityTokenProperty))
                {
                    _properties.Remove(SecurityTokenProperty);
                }

                _properties[SecurityTokenProperty] = value;
            }
        }

        /// <summary>
        /// Gets or sets the SessionState
        /// </summary>
        public string SessionState
        {
            get
            {
                string value;
                return _properties.TryGetValue(SessionStateProperty, out value) ? value : null;
            }
            set
            {
                if (_properties.ContainsKey(SecurityTokenProperty))
                {
                    _properties.Remove(SecurityTokenProperty);
                }

                _properties[SessionStateProperty] = value;
            }
        }
    }
}
