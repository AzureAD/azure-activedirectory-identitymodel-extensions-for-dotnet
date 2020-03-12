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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a RequestedSecurityToken element.
    /// <see cref="RequestedSecurityToken"/> represents the security token returned in a WsTrust response.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class RequestedSecurityToken
    {
        private SecurityToken _securityToken;
        private string _token;

        /// <summary>
        /// Creates an instance of <see cref="RequestedSecurityToken"/>.
        /// This constructor is useful when deserializing from a stream such as xml.
        /// </summary>
        public RequestedSecurityToken()
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedSecurityToken"/>.
        /// </summary>
        /// <param name="token">a security token</param>
        /// <exception cref="ArgumentNullException">if <paramref name="token"/> is null or empty.</exception>
        public RequestedSecurityToken(string token)
        {
            Token = token;
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedSecurityToken"/>.
        /// </summary>
        /// <param name="securityToken">a <see cref="SecurityToken"/>.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="securityToken"/> is null.</exception>
        public RequestedSecurityToken(SecurityToken securityToken)
        {
            SecurityToken = securityToken;
        }

        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        /// <exception cref="ArgumentNullException">if Token is null or empty string.</exception>
        public string Token
        {
            get => _token;
            set => _token = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(Token)) : value; }


        /// <summary>
        /// Gets or set the <see cref="SecurityToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if SecurityToken is null.</exception>
        public SecurityToken SecurityToken
        {
            get => _securityToken;
            set => _securityToken = value ?? throw LogHelper.LogArgumentNullException(nameof(SecurityToken));
        }
    }
}
