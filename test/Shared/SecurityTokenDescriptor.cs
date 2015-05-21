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

namespace System.IdentityModel.Test
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.IdentityModel.Tokens;

    /// <summary>
    /// This is a place holder for all the attributes related to the issued token.
    /// </summary>
    public class SecurityTokenDescriptor
    {
        /// <summary>
        /// Claims to put into the token
        /// </summary>
        /// 
        public IEnumerable<Claim> Claims { get; set; }

        /// <summary>
        /// Gets or sets the issued at time
        /// </summary>
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Gets or sets the audience
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the issuer
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the issued at time
        /// </summary>
        public DateTime? IssuedAt { get; set; }

        /// <summary>
        /// Gets or sets the notbefore time
        /// </summary>
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Gets or sets the credentials used to sign the token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }


    }
}
