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
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsFed;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the Claims element.
    /// The Claims element contains specific claims that are being requested.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class Claims
    {
        /// <summary>
        /// Creates an instance of <see cref="Claims"/>
        /// </summary>
        /// <param name="dialect">a uri that defines the dialect of the claims.</param>
        /// <param name="claimTypes">a list of <see cref="ClaimType"/>.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="dialect"/> is null or empty, <paramref name="claimTypes"/> is null.</exception>
        public Claims(string dialect, IList<ClaimType> claimTypes)
        {
            Dialect = string.IsNullOrEmpty(dialect) ? throw LogHelper.LogArgumentNullException(nameof(dialect)) : dialect;
            ClaimTypes = claimTypes ?? throw LogHelper.LogArgumentNullException(nameof(claimTypes));
        }

        /// <summary>
        /// Gets the list of <see cref="ClaimType"/>.
        /// </summary>
        public IList<ClaimType> ClaimTypes { get; }

        /// <summary>
        /// Gets the dialect of these claims.
        /// </summary>
        public string Dialect { get; set;  }
    }
}
