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
using System.Globalization;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a Rsa security key.
    /// </summary>
    public class RsaSecurityKey : AsymmetricSecurityKey
    {
        private bool? _hasPrivateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSecurityKey"/> class.
        /// </summary>
        /// <param name="rsaParameters"><see cref="RSAParameters"/></param>
        public RsaSecurityKey(RSAParameters rsaParameters)
        {
            // must have modulus and exponent otherwise the crypto operations fail later
            if (rsaParameters.Modulus == null || rsaParameters.Exponent == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10700, rsaParameters.ToString())));

            _hasPrivateKey = rsaParameters.D != null && rsaParameters.DP != null && rsaParameters.DQ != null && rsaParameters.P != null && rsaParameters.Q != null && rsaParameters.InverseQ != null;
            Parameters = rsaParameters;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSecurityKey"/> class.
        /// </summary>
        /// <param name="rsa"><see cref="RSA"/></param>
        public RsaSecurityKey(RSA rsa)
        {
            if (rsa == null)
                throw LogHelper.LogArgumentNullException("rsa");

            Rsa = rsa;
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        public override bool HasPrivateKey
        {
            get
            {

                if (_hasPrivateKey == null)
                {
                    try
                    {
                        // imitate signing
                        byte[] hash = new byte[20];
#if NETSTANDARD1_4
                        Rsa.SignData(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
#else
                        RSACryptoServiceProvider rsaCryptoServiceProvider = Rsa as RSACryptoServiceProvider;
                        if (rsaCryptoServiceProvider != null)
                            rsaCryptoServiceProvider.SignData(hash, SecurityAlgorithms.Sha256);
                        else
                            Rsa.DecryptValue(hash);
#endif
                        _hasPrivateKey = true;
                    }
                    catch (CryptographicException)
                    {
                        _hasPrivateKey = false;
                    }
                }
                return _hasPrivateKey.Value;
            }
        }

        /// <summary>
        /// Gets RSA key size.
        /// </summary>
        public override int KeySize
        {
            get
            {
                if (Rsa != null)
                    return Rsa.KeySize;
                else if (Parameters.Modulus != null)
                    return Parameters.Modulus.Length * 8;
                else
                    return 0;
            }
        }

        /// <summary>
        /// <see cref="RSAParameters"/> used to initialize the key.
        /// </summary>
        public RSAParameters Parameters { get; private set; }

        /// <summary>
        /// <see cref="RSA"/> instance used to initialize the key.
        /// </summary>
        public RSA Rsa { get; private set; }
    }
}
