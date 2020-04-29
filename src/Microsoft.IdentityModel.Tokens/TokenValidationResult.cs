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
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains artifacts obtained when a SecurityToken is validated.
    /// </summary>
    public class TokenValidationResult
    {
        /// <summary>
        /// The <see cref="ClaimsIdentity"/> created from the validated security token.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="Exception"/> that occurred during validation.
        /// </summary>
        public Exception Exception { get; set; }

        /// <summary>
        /// Gets or sets the issuer that was found in the token.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// True if the token was successfully validated, false otherwise.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityToken"/> that was validated.
        /// </summary>
        public SecurityToken SecurityToken { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="CallContext"/> that contains call information.
        /// </summary>
        public CallContext TokenContext { get; set; }

        /// <summary>
        /// Gets or sets the token type of the <see cref="SecurityToken"/> that was validated.
        /// When a <see cref="TokenValidationParameters.TypeValidator"/> is registered,
        /// the type returned by the delegate is used to populate this property.
        /// Otherwise, the type is resolved from the token itself, if available
        /// (e.g for a JSON Web Token, from the "typ" header). 
        /// </summary>
        public string TokenType { get; set; }
    }
}
