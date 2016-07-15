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
    /// Helper class to conver <see cref="JwtMimeType"/> from string value.
    /// Note that the string here is usually not a full MIME type string begins
    ///  with "application/" but a compact version where the "application/"
    ///  prefix is omitted.
    /// See https://tools.ietf.org/html/rfc7515#section-4.1.10 for details.
    /// </summary>
    public class JwtMimeTypeHelper
    {
        /// <summary>
        /// The application prefix of a MIME type.
        /// </summary>
        public const string ApplicationPrefix = "application/";

        /// <summary>
        /// The string representing JSON MIME type.
        /// </summary>
        public const string JsonMimeType = "JSON";

        /// <summary>
        /// The string representing JSON MIME type.
        /// </summary>
        public const string JoseMineType = "JOSE";

        /// <summary>
        /// The string representing JOSE+JSON MIME type.
        /// </summary>
        public const string JoseAndJsonMineType = "JOSE+JSON";

        /// <summary>
        /// The string representing JWE MIME type.
        /// Note that this value is not defined in any of the JWT related RFCs.
        /// We support this value for backward compatibility but it's not
        ///  recommended for new implementations.
        /// It is required to use JWT (https://tools.ietf.org/html/rfc7519#section-5.1)
        ///  or JOSE/JOSE+JSON (https://tools.ietf.org/html/rfc7515#section-4.1.9)
        /// </summary>
        public const string JweMineType = "JWE";

        /// <summary>
        /// The string representing JWS MIME type.
        /// Note that this value is not defined in any of the JWT related RFCs.
        /// We support this value for backward compatibility but it's not
        ///  recommended for new implementations.
        /// It is required to use JWT (https://tools.ietf.org/html/rfc7519#section-5.1)
        ///  or JOSE/JOSE+JSON (https://tools.ietf.org/html/rfc7515#section-4.1.9)
        /// </summary>
        public const string JwsMineType = "JWS";

        /// <summary>
        /// The string representing JWT MIME type.
        /// </summary>
        public const string JsonTokenMineType = "JWT";

        /// <summary>
        /// The prosed mime type for JWT in one of the draft OpenId SPEC:
        ///  https://openid.net/specs/draft-jones-json-web-token-07.html
        /// Note that this value is incompatible with the final JWT RFC 7519.
        /// We support this value for backward compatibility but it's not
        ///  recommended for new implementations.
        /// JWT is always the better choice when applicable; or even better to
        ///  use JOSE or JOSE+JSON defined in https://tools.ietf.org/html/rfc7515#section-4.1.9
        ///  which also tells the serialization mode of the JWT.
        /// </summary>
        public const string OpenIdJwtMineType = "http://openid.net/specs/jwt/1.0";

        /// <summary>
        /// Parses a given Typ or Cty value string to <see cref="JwtMimeType"/>.
        /// </summary>
        /// <param name="typeString">The Typ or Cty value string to parse.</param>
        /// <returns>The <see cref="JwtMimeType"/> repreenting the corresponded media type.</returns>
        public static JwtMimeType FromString(string typeString)
        {
            typeString = typeString.Trim();
            if (string.IsNullOrEmpty(typeString))
            {
                return JwtMimeType.Empty;
            }

            // Omit the application prefix if existing.
            // Note that this is not fully compatible with the RFC (https://tools.ietf.org/html/rfc7515#section-4.1.9)
            //  but it's good enough for the purpose of this method.
            // It's not supposed to be used to convert a full MIME type string to the compact format.
            if (typeString.StartsWith(ApplicationPrefix, StringComparison.Ordinal))
            {
                typeString = typeString.Substring(ApplicationPrefix.Length);
            }

            // Determine the MIME type using ordinal string-comparison.
            switch (typeString.Trim())
            {
                case JsonMimeType:
                    return JwtMimeType.JSON;

                case JoseMineType:
                    return JwtMimeType.JOSE;

                case JoseAndJsonMineType:
                    return JwtMimeType.JOSEANDJSON;

                case JweMineType:
                case JwsMineType:
                case OpenIdJwtMineType:
                case JsonTokenMineType:
                    return JwtMimeType.JWT;

                default:
                    return JwtMimeType.Other;
            }
        }
    }
}
