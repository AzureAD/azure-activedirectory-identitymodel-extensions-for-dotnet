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
    /// List of header parameter names see: http://tools.ietf.org/html/rfc7519#section-5.
    /// </summary>
    public struct JwtHeaderParameterNames
    {
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public const string Alg = "alg";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public const string Cty = "cty";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public const string Enc = "enc";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        /// </summary>
        public const string IV = "iv";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.2
        /// </summary>
        public const string Jku = "jku";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public const string Jwk = "jwk";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public const string Kid = "kid";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public const string X5c = "x5c";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public const string X5t = "x5t";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string X5u = "x5u";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public const string Zip = "zip";
    }
}
