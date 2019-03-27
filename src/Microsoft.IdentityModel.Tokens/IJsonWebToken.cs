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
    /// Interface for a json web token (JWT).
    /// </summary>
    public interface IJsonWebToken : ISecurityToken
    {
        /// <summary>
        /// This must be implemented to get the Actor of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Actor { get; }

        /// <summary>
        /// This must be implemented to get the Algorithm used when signing this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Alg { get; }

        /// <summary>
        /// This must be implemented to get the Audiences of this <see cref="IJsonWebToken"/>.
        /// </summary>
        IEnumerable<string> Audiences { get; }

        /// <summary>
        /// This must be implemented to get the <see cref="Claim"/>s for each value in the JWT payload.
        /// </summary>
        IEnumerable<Claim> Claims { get; }

        /// <summary>
        /// This must be implemented to get the Content Type of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Cty { get; }

        /// <summary>
        /// This must be implemented to get the Encryption Algorithm of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Enc { get; }

        /// <summary>
        /// This must be implemented to get the time this <see cref="IJsonWebToken"/> was issued at.
        /// </summary>
        DateTime IssuedAt { get; }

        /// <summary>
        /// This must be implemented to get the key ID of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Kid { get; }

        /// <summary>
        /// This must be implemented to get the Subject of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Subject { get; }

        /// <summary>
        /// This must be implemented to get the Type of this <see cref="IJsonWebToken"/>.
        /// </summary>
        string Typ { get; }

        /// <summary>
        /// This must be implemented to get the X509 Certificate Thumbprint associated with this <see cref="IJsonWebToken"/>.
        /// </summary>
        string X5t { get; }

        /// <summary>
        /// This must be implemented to obtain a 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        T GetPayloadValue<T>(string key);

        /// <summary>
        /// This must be implemented to get the 'value' corresponding to the provided key from the JWT payload { key, 'value' }.
        /// </summary>
        /// <remarks>This should return 'true' if 'value' is found, and 'false' otherwise.</remarks>

        bool TryGetPayloadValue<T>(string key, out T value);

        /// <summary>
        /// This must be implemented to get the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        T GetHeaderValue<T>(string key);

        /// <summary>
        /// This must be implemented to get the 'value' corresponding to the provided key from the JWT header { key, 'value' }.
        /// </summary>
        /// <remarks>This should return 'true' if 'value' is found, and 'false' otherwise.</remarks>
        bool TryGetHeaderValue<T>(string key, out T value);
    }
}
