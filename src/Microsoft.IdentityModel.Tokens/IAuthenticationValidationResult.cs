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

using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains artifacts obtained when a full authentication scheme is validated.
    /// </summary>
    /// <remarks>The model is an interface so as to allow for extensibility across different frameworks.</remarks>
    public interface IAuthenticationValidationResult

    {
        /// <summary>
        /// Denotes the schemes that was used to authenticate the actor and subject identities.
        /// </summary>
        /// <remarks>The common examples are Bearer and PoP authorization header schemes.</remarks>
        public string AuthenticationScheme { get; set; }

        /// <summary>
        /// Contains the subject that was validated in the authentication process.
        /// </summary>
        /// <remarks>The token type of the subject token is filled out inside <see cref="TokenValidationResult.TokenType"/></remarks>
        public TokenValidationResult SubjectTokenValidationResult { get; set; }

        /// <summary>
        /// Claimed based identity representing the Actor.
        /// </summary>
        /// <remarks>The type is not a <see cref="TokenValidationResult"/> as the actor identity can be proven through other means; e.g. client certificates.</remarks>
        public ClaimsIdentity ActorIdentity { get; set; }
    }
}
