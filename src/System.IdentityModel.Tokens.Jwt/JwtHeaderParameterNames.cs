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
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Alg = "alg";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Cty = "cty";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Kid = "kid";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Jku = "jku";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Jwk = "jwk";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string X5c = "x5c";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string X5t = "x5t";

        /// <summary>
        /// see:http://tools.ietf.org/html/rfc7519#section-5
        /// </summary>
        public const string X5u = "x5u";
    }
}
