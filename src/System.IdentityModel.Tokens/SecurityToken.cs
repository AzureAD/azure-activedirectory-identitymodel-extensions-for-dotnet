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

using System;

namespace System.IdentityModel.Tokens
{
    public abstract class SecurityToken
    {
        public abstract string Id { get; }
        public abstract SecurityKey SecurityKey { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="JwtSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public abstract SecurityKey SigningKey
        {
            get;
            set;
        }

        public abstract String Issuer { get; }
        public abstract DateTime ValidFrom { get; }
        public abstract DateTime ValidTo { get; }
    }
}
