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
    /// List of algorithms see: http://tools.ietf.org/html/rfc7518#section-3
    /// </summary>
    public struct JwtAlgorithms
    {
        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string ECDSA_SHA256    = "ES256";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string ECDSA_SHA384    = "ES384";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string ECDSA_SHA512    = "ES512";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string HMAC_SHA256     = "HS256";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string HMAC_SHA384     = "HS384";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string HMAC_SHA512     = "HS512";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string NONE            = "none";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string RSA_SHA256      = "RS256";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string RSA_SHA384      = "RS384";

        /// <summary>
        /// see: http://tools.ietf.org/html/rfc7518#section-3
        /// </summary>
        public const string RSA_SHA512      = "RS512";
    }
}
