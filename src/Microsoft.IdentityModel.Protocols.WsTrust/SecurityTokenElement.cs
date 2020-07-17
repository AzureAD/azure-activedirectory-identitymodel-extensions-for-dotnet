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
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The <see cref="SecurityTokenElement"/> is used to represent a <see cref="SecurityToken"/> to provide serialization for key material and security tokens.
    /// </summary>
    public class SecurityTokenElement
    {
        /// <summary>
        /// Creates an instance of <see cref="SecurityTokenElement"/>.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/>that will be serialized.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityToken"/> is null.</exception>
        public SecurityTokenElement(SecurityToken securityToken)
        {
            SecurityToken = securityToken ?? throw LogHelper.LogArgumentNullException(nameof(securityToken));
        }

        /// <summary>
        /// Creates an instance of <see cref="SecurityTokenElement"/>.
        /// </summary>
        /// <param name="securityTokenReference">the <see cref="SecurityTokenReference"/> that will be serialized.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityTokenReference"/> is null.</exception>
        public SecurityTokenElement(SecurityTokenReference securityTokenReference)
        {
            SecurityTokenReference = securityTokenReference ?? throw LogHelper.LogArgumentNullException(nameof(securityTokenReference));
        }

        /// <summary>
        /// Gets the <see cref="SecurityToken"/>.
        /// </summary>
        public SecurityToken SecurityToken { get; }

        /// <summary>
        /// Gets the <see cref="SecurityTokenReference"/>.
        /// </summary>
        public SecurityTokenReference SecurityTokenReference { get; }
    }
}
