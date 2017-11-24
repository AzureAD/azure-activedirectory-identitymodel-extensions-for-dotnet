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
    /// Represents a Rsa security key.
    /// </summary>
    public class RsaSecurityKey : AsymmetricSecurityKey
    {
        private bool? _hasPrivateKey;

        private bool _foundPrivateKeyDetermined = false;

        private PrivateKeyStatus _foundPrivateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaSecurityKey"/> class.
        /// </summary>
        /// <param name="rsaParameters"><see cref="RSAParameters"/></param>
        public RsaSecurityKey(RSAParameters rsaParameters)
        {
#if (NET45 || NET451)
            rsaParameters = RemoveLeadingZero(rsaParameters);
#endif
            // must have modulus and exponent otherwise the crypto operations fail later
            if (rsaParameters.Modulus == null || rsaParameters.Exponent == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10700, rsaParameters.ToString())));

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
#if (NET45 || NET451)
            if (rsa as RSACryptoServiceProvider != null)
            {
                try
                {
                    var parameters = rsa.ExportParameters(true);
                    parameters = RemoveLeadingZero(parameters);
                    rsa.ImportParameters(parameters);
                }
                catch (Exception)
                {
                    try
                    {
                        var parameters = rsa.ExportParameters(false);
                        parameters = RemoveLeadingZero(parameters);
                        rsa.ImportParameters(parameters);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
#endif
            Rsa = rsa;
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [System.Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
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
        /// Gets an enum indicating if a private key exists.
        /// </summary>
        /// <return>'Exists' if private key exists for sure; 'DoesNotExist' if private key doesn't exist for sure; 'Unknown' if we cannot determine.</return>
        public override PrivateKeyStatus PrivateKeyStatus
        {
            get
            {
                if (_foundPrivateKeyDetermined)
                    return _foundPrivateKey;

                _foundPrivateKeyDetermined = true;

                if (Rsa != null)
                {
                    try
                    {
                        Parameters = Rsa.ExportParameters(true);                       
                    }
                    catch(Exception)
                    {
                        _foundPrivateKey = PrivateKeyStatus.Unknown;
                        return _foundPrivateKey;
                    }
                }

                if (Parameters.D != null && Parameters.DP != null && Parameters.DQ != null &&
                    Parameters.P != null && Parameters.Q != null && Parameters.InverseQ != null)
                    _foundPrivateKey = PrivateKeyStatus.Exists;
                else
                    _foundPrivateKey = PrivateKeyStatus.DoesNotExist;

                return _foundPrivateKey;
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

        private RSAParameters RemoveLeadingZero(RSAParameters rsaParameters)
        {
            // Sometimes the parameters we received have a leading 0, the reason is the parameters 
            // are positive integers, the generator of RSA key may put a leading 0 as the sign
            // digit. RSACng will ignore the leading 0, but RSACryptoServiceProvider doesn't, so
            // we have to remove the leading 0 for .NET framework.
            rsaParameters.Modulus = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.Modulus);
            rsaParameters.Exponent = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.Exponent);
            rsaParameters.D = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.D);
            rsaParameters.P = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.P);
            rsaParameters.Q = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.Q);
            rsaParameters.DP = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.DP);
            rsaParameters.DQ = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.DQ);
            rsaParameters.InverseQ = RemoveLeadingZeroInBase64UrlDecodedBytes(rsaParameters.InverseQ);
            return rsaParameters;
        }

        private byte[] RemoveLeadingZeroInBase64UrlDecodedBytes(byte[] bytes)
        {
            if (bytes == null)
                return bytes;

            var n = bytes.Length;
            if (n > 0 && bytes[0].Equals(0x00))
            {
                // remove the leading zero in the decoded bytes
                var newBytes = new byte[n - 1];
                Buffer.BlockCopy(bytes, 1, newBytes, 0, n - 1);
                return newBytes;
            }

            return bytes;
        }
    }
}
