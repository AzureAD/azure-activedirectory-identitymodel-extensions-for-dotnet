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
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains some information which used to create a security token.
    /// </summary>
    public class SecurityTokenDescriptor
    {
        /// <summary>
        /// Gets or sets the value of the 'audience' claim.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Defines the compression algorithm that will be used to compress the JWT token payload.
        /// </summary>
        public string CompressionAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="EncryptingCredentials"/> used to create a encrypted security token.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials { get; set; }

        /// <summary>
        /// Gets or sets the value of the 'expiration' claim.
        /// </summary>
        public DateTime? Expires { get; set; }

        /// <summary>
        /// Gets or sets the issuer of this <see cref="SecurityTokenDescriptor"/>.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the time the security token was issued.
        /// </summary>
        public DateTime? IssuedAt { get; set; }

        /// <summary>
        /// Gets or sets the notbefore time for the security token.
        /// </summary>
        public DateTime? NotBefore { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="Dictionary{TKey, TValue}"/> which represents the claims that will be used when creating a security token.
        /// If both <cref see="Claims"/> and <see cref="Subject"/> are set, the claim values in Subject will be combined with the values
        /// in Claims. The values found in Claims take precedence over those found in Subject, so any duplicate
        /// values will be overridden.
        /// </summary>
        public IDictionary<string, object> Claims { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SigningCredentials"/> used to create a security token.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="ClaimsIdentity"/>.
        /// If both <cref see="Claims"/> and <see cref="Subject"/> are set, the claim values in Subject will be combined with the values
        /// in Claims. The values found in Claims take precedence over those found in Subject, so any duplicate
        /// values will be overridden.
        /// </summary>
        public ClaimsIdentity Subject { get; set; }
    }
}
