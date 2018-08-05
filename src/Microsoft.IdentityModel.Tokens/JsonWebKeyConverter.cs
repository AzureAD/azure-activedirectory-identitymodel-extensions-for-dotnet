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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Converts a <see cref="SecurityKey"/> into a <see cref="JsonWebKey"/>
    /// Supports: <see cref="RsaSecurityKey"/>, <see cref="X509SecurityKey"/> and <see cref=" SymmetricSecurityKey"/>.
    /// </summary>
    public class JsonWebKeyConverter
    {
        /// <summary>
        /// Converts a <see cref="SecurityKey"/> into a <see cref="JsonWebKey"/>
        /// </summary>
        /// <param name="key">a <see cref="SecurityKey"/> to convert.</param>
        /// <returns>a <see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        /// <exception cref="NotSupportedException">if <paramref name="key"/>is not a supported type.</exception>
        /// <remarks>Supports: <see cref="RsaSecurityKey"/>, <see cref="X509SecurityKey"/> and <see cref=" SymmetricSecurityKey"/>.</remarks>
        public static JsonWebKey ConvertFromSecurityKey(SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (key is RsaSecurityKey rsaKey)
                return ConvertFromRSASecurityKey(rsaKey);
            else if (key is SymmetricSecurityKey symmetricKey)
                return ConvertFromSymmetricSecurityKey(symmetricKey);
            else if (key is X509SecurityKey x509Key)
                return ConvertFromX509SecurityKey(x509Key);
            else
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10674, key.GetType().FullName)));
        }

        /// <summary>
        /// Converts a <see cref="RsaSecurityKey"/> into a <see cref="JsonWebKey"/>
        /// </summary>
        /// <param name="key">a <see cref="RsaSecurityKey"/> to convert.</param>
        /// <returns>a <see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        public static JsonWebKey ConvertFromRSASecurityKey(RsaSecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            var jsonWebKey = new JsonWebKey();
            var parameters = new RSAParameters();
            jsonWebKey.Kty = JsonWebAlgorithmsKeyTypes.RSA;
            jsonWebKey.Kid = key.KeyId;

            // get Parameters
            if (key.Rsa != null)
                parameters = key.Rsa.ExportParameters(true);
            else
                parameters = key.Parameters;

            jsonWebKey.N = parameters.Modulus != null ? Base64UrlEncoder.Encode(parameters.Modulus) : null;
            jsonWebKey.E = parameters.Exponent != null ? Base64UrlEncoder.Encode(parameters.Exponent) : null;
            jsonWebKey.D = parameters.D != null ? Base64UrlEncoder.Encode(parameters.D) : null;
            jsonWebKey.P = parameters.P != null ? Base64UrlEncoder.Encode(parameters.P) : null;
            jsonWebKey.Q = parameters.Q != null ? Base64UrlEncoder.Encode(parameters.Q) : null;
            jsonWebKey.DP = parameters.DP != null ? Base64UrlEncoder.Encode(parameters.DP) : null;
            jsonWebKey.DQ = parameters.DQ != null ? Base64UrlEncoder.Encode(parameters.DQ) : null;
            jsonWebKey.QI = parameters.InverseQ != null ? Base64UrlEncoder.Encode(parameters.InverseQ) : null;

            return jsonWebKey;
        }

        /// <summary>
        /// Converts a <see cref="X509SecurityKey"/> into a <see cref="JsonWebKey"/>
        /// </summary>
        /// <param name="key">a <see cref="X509SecurityKey"/> to convert.</param>
        /// <returns>a <see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        public static JsonWebKey ConvertFromX509SecurityKey(X509SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            var jsonWebKey = new JsonWebKey();
            jsonWebKey.Kty = JsonWebAlgorithmsKeyTypes.RSA;
            jsonWebKey.Kid = key.KeyId;
            jsonWebKey.X5t = key.X5t;
            if (key.Certificate.RawData != null)
                jsonWebKey.X5c.Add(Convert.ToBase64String(key.Certificate.RawData));

            return jsonWebKey;
        }

        /// <summary>
        /// Converts a <see cref="SymmetricSecurityKey"/> into a <see cref="JsonWebKey"/>
        /// </summary>
        /// <param name="key">a <see cref="SymmetricSecurityKey"/> to convert.</param>
        /// <returns>a <see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        public static JsonWebKey ConvertFromSymmetricSecurityKey(SymmetricSecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            return new JsonWebKey
            {
                K = Base64UrlEncoder.Encode(key.Key),
                Kid = key.KeyId,
                Kty = JsonWebAlgorithmsKeyTypes.Octet
            };
        }
    }
}
