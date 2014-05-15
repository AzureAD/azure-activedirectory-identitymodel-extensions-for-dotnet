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
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains WsFederation metadata that can be populated from a xml string.
    /// </summary>
    public class WsFederationMetadata
    {
        private Collection<SecurityKey> _signingKeys = new Collection<SecurityKey>();

        /// <summary>
        /// Initializes an new instance of <see cref="WsFederationMetadata"/>.
        /// </summary>
        public WsFederationMetadata()
        {           
        }

        /// <summary>
        /// Gets or sets the token issuer.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets the <see cref="ICollection[SecurityKey]"/> that the IdentityProvider indicates are to be used signing tokens.
        /// </summary>
        public ICollection<SecurityKey> SigningKeys
        {
            get
            {
                return _signingKeys;
            }
        }

        /// <summary>
        /// Gets or sets the Gets or sets the passive token endpoint.
        /// </summary>
        public string TokenEndpoint { get; set; }
    }
}
