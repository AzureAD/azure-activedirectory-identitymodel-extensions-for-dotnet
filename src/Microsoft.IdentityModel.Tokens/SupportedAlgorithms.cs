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

using Microsoft.IdentityModel.Logging;
using System;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines the default set of algorithms this library supports
    /// </summary>
    internal static class SupportedAlgorithms
    {
        /// <summary>
        /// Checks if an 'algorithm, key' pair is supported.
        /// </summary>
        /// <param name="algorithm">the algorithm to check.</param>
        /// <param name="key">the <see cref="SecurityKey"/>.</param>
        /// <returns>true if 'algorithm, key' pair is supported.</returns>
        public static bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (key as RsaSecurityKey != null)
                return IsSupportedRsaAlgorithm(algorithm, key);

            if (key is X509SecurityKey x509Key)
            {
                // only RSA keys are supported
                if (x509Key.PublicKey as RSA == null)
                    return false;

                return IsSupportedRsaAlgorithm(algorithm, key);
            }

            if (key is JsonWebKey jsonWebKey)
            {
                if (JsonWebAlgorithmsKeyTypes.RSA.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedRsaAlgorithm(algorithm, key);
                else if (JsonWebAlgorithmsKeyTypes.EllipticCurve.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedEcdsaAlgorithm(algorithm);
                else if (JsonWebAlgorithmsKeyTypes.Octet.Equals(jsonWebKey.Kty, StringComparison.Ordinal))
                    return IsSupportedSymmetricAlgorithm(algorithm);

                return false;
            }

            if (key is ECDsaSecurityKey)
                return IsSupportedEcdsaAlgorithm(algorithm);

            if (key as SymmetricSecurityKey != null)
                return IsSupportedSymmetricAlgorithm(algorithm);

            return false;
        }

        internal static bool IsSupportedAuthenticatedEncryptionAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!(algorithm.Equals(SecurityAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal)))
                return false;

            if (key is SymmetricSecurityKey)
                return true;

            if (key is JsonWebKey jsonWebKey)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        private static bool IsSupportedEcdsaAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                    return true;
            }

            return false;
        }

        internal static bool IsSupportedHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                case SecurityAlgorithms.Sha256Digest:
                case SecurityAlgorithms.Sha384:
                case SecurityAlgorithms.Sha384Digest:
                case SecurityAlgorithms.Sha512:
                case SecurityAlgorithms.Sha512Digest:
                    return true;

                default:
                    return false;
            }
        }

        internal static bool IsSupportedKeyWrapAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOaepKeyWrap, StringComparison.Ordinal))
            {
                if (key is RsaSecurityKey)
                    return true;

                if (key is X509SecurityKey)
                    return true;

                if (key is JsonWebKey jsonWebKey && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return true;
            }

            return false;
        }

        internal static bool IsSupportedRsaAlgorithm(string algorithm, SecurityKey key)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RsaOAEP:
                case SecurityAlgorithms.RsaPKCS1:
                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return true;
                case SecurityAlgorithms.RsaSsaPssSha256:
                case SecurityAlgorithms.RsaSsaPssSha384:
                case SecurityAlgorithms.RsaSsaPssSha512:
                case SecurityAlgorithms.RsaSsaPssSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha384Signature:
                case SecurityAlgorithms.RsaSsaPssSha512Signature:
                    return IsSupportedRsaPss(key);
            }

            return false;
        }

        private static bool IsSupportedRsaPss(SecurityKey key)
        {
#if NET45
            // RSA-PSS is not available on .NET 4.5
            LogHelper.LogInformation(LogMessages.IDX10692);
            return false;
#elif NET461 || NETSTANDARD2_0
            // RSACryptoServiceProvider doesn't support RSA-PSS
            if (key is RsaSecurityKey rsa && rsa.Rsa is RSACryptoServiceProvider)
            {
                LogHelper.LogInformation(LogMessages.IDX10693);
                return false;
            }
            else if (key is X509SecurityKey x509SecurityKey && x509SecurityKey.PublicKey is RSACryptoServiceProvider)
            {
                LogHelper.LogInformation(LogMessages.IDX10693);
                return false;
            }
            else
            {
                return true;
            }
#else
            return true;
#endif
        }

        internal static bool IsSupportedSymmetricAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                case SecurityAlgorithms.Aes192CbcHmacSha384:
                case SecurityAlgorithms.Aes256CbcHmacSha512:
                case SecurityAlgorithms.Aes128KW:
                case SecurityAlgorithms.Aes256KW:
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.HmacSha512:
                    return true;
            }

            return false;
        }
    }
}
