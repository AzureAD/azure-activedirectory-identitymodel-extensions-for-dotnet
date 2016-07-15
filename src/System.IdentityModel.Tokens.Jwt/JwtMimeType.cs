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

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Defines the mdeia type of a JWT or the contents contained by a JWT.
    /// This is used by JOSE headers (<see cref="JwtHeader"/>) to define:
    /// - The mdeia type of the complete JWT (the typ parameter of the JOSE header).
    /// - The mdeia type of the secured content (the cty parameter of the JOSE header).
    /// </summary>
    public enum JwtMimeType
    {
        /// <summary>
        /// The type of the content is undefined.
        /// </summary>
        Empty,

        /// <summary>
        /// The content is JSON; usually a set of claims under the context of JWT.
        /// </summary>
        JSON,

        /// <summary>
        /// The contect is a JWT (JWS or JWE) serialized in compact format.
        /// </summary>
        JOSE,

        /// <summary>
        /// The contect is a JWT (JWS or JWE) serialized in full (JSON) format.
        /// </summary>
        JOSEANDJSON,

        /// <summary>
        /// The contect is a JWT (JWS or JWE) while its serialization mode is unspecified.
        /// </summary>
        JWT,

        /// <summary>
        /// The content is some other type not defined in this enum.
        /// </summary>
        Other,
    }
}
