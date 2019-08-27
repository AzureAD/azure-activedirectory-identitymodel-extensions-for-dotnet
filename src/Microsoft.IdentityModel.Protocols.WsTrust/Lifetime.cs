//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Used in the RequestSecurityToken or RequestSecurityTokenResponse to indicated the desired or 
    /// required lifetime of a token. Everything here is stored in UTC format.
    /// </summary>
    public class Lifetime
    {
        /// <summary>
        /// Instantiates a LifeTime object with token creation and expiration time in Utc.
        /// </summary>
        /// <param name="created">Token creation time in Utc.</param>
        /// <param name="expires">Token expiration time in Utc.</param>
        /// <exception cref="ArgumentException">When the given expiration time is 
        /// before the given creation time.</exception>
        public Lifetime( DateTime created, DateTime expires )
            : this( (DateTime?)created, (DateTime?)expires )
        {
        }

        /// <summary>
        /// Instantiates a LifeTime object with token creation and expiration time in Utc.
        /// </summary>
        /// <param name="created">Token creation time in Utc.</param>
        /// <param name="expires">Token expiration time in Utc.</param>
        /// <exception cref="ArgumentException">When the given expiration time is 
        /// before the given creation time.</exception>
        public Lifetime( DateTime? created, DateTime? expires )
        {
            if ( created.HasValue && expires.HasValue && expires.Value <= created.Value )
                throw LogHelper.LogExceptionMessage(new ArgumentException("expires < created"));

            Created = created;
            Expires = expires;
        }

        /// <summary>
        /// Gets the token creation time in UTC time.
        /// </summary>
        public DateTime? Created { get; set; }

        /// <summary>
        /// Gets the token expiration time in UTC time.
        /// </summary>
        public DateTime? Expires { get; set; }
    }
}
