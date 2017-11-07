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
    /// Json web key converter
    /// </summary>
    public class JsonWebKeyConverter
    {
        /// <summary>
        /// Convert security key into json web key.
        /// </summary>
        /// <param name="key">Security Key</param>
        /// <returns>json web key</returns>
        public static JsonWebKey ConvertFromSecurityKey(SecurityKey key)
        {
            if (key.GetType() == typeof(RsaSecurityKey))
                return ConvertFromRSASecurityKey(key as RsaSecurityKey);
            else if (key.GetType() == typeof(SymmetricSecurityKey))
                return ConvertFromSymmetricSecurityKey(key as SymmetricSecurityKey);
            else if (key.GetType() == typeof(X509SecurityKey))
                return ConvertFromX509SecurityKey(key as X509SecurityKey);
            else
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10674, key.GetType().FullName)));
        }

        /// <summary>
        /// Convert RSA security key into json web key.
        /// </summary>
        /// <param name="key">RSA security key</param>
        /// <returns>json web key</returns>
        public static JsonWebKey ConvertFromRSASecurityKey(RsaSecurityKey key)
        {
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
        /// Convert X509 security key into json web key.
        /// </summary>
        /// <param name="key">X509 security key</param>
        /// <returns>json web key</returns>
        public static JsonWebKey ConvertFromX509SecurityKey(X509SecurityKey key)
        {
            var jsonWebKey = new JsonWebKey();
            jsonWebKey.Kty = JsonWebAlgorithmsKeyTypes.RSA;
            jsonWebKey.Kid = key.KeyId;
            jsonWebKey.X5t = key.X5t;
            if (key.Certificate.RawData != null)
                jsonWebKey.X5c.Add(Convert.ToBase64String(key.Certificate.RawData));
            return jsonWebKey;
        }

        /// <summary>
        /// Convert Symmetric security key into json web key.
        /// </summary>
        /// <param name="key">Symmetric security key</param>
        /// <returns>json web key</returns>
        public static JsonWebKey ConvertFromSymmetricSecurityKey(SymmetricSecurityKey key)
        {
            var jsonWebKey = new JsonWebKey();
            jsonWebKey.K = Base64UrlEncoder.Encode(key.Key);
            jsonWebKey.Kid = key.KeyId;
            jsonWebKey.Kty = JsonWebAlgorithmsKeyTypes.Octet;
            return jsonWebKey;
        }
    }
}
