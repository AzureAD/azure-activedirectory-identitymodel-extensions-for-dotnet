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
    /// Generates Combined and 
    /// </summary>
    public static class Psha1KeyGenerator
    {
        private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

        //
        // 1/(2^32) keys will be weak.  20 random keys will never happen by chance without the RNG being messed up.
        //
        const int _maxKeyIterations = 20;
        static int s_minKeySizeInBits = 16 * 8; // 16 Bytes - 128 bits.
        static int s_maxKeySizeInBits = (16 * 1024) * 8; // 16 K

        /// <summary>
        /// Computes the session key based on PSHA1 algorithm.
        /// </summary>
        /// <param name="requestorEntropy">The entropy from the requestor side.</param>
        /// <param name="issuerEntropy">The entropy from the token issuer side.</param>
        /// <param name="keySizeInBits">The desired key size in bits.</param>
        /// <returns>The computed session key.</returns>
        /// 
        public static byte[] ComputeCombinedKey(byte[] issuerEntropy, byte[] requestorEntropy, int keySizeInBits)
        {
            if (requestorEntropy == null)
                throw LogHelper.LogArgumentNullException(nameof(requestorEntropy));

            if (issuerEntropy == null)
                throw LogHelper.LogArgumentNullException(nameof(issuerEntropy));

            // Do a sanity check here. We don't want to allow invalid keys or keys that are too large.
            if ((keySizeInBits < s_minKeySizeInBits) || (keySizeInBits > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid key size. Key size requested: '{0}', must be larger than '{1}' and smaller than '{2}'.", keySizeInBits, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(keySizeInBits)));

            if ((issuerEntropy.Length * 8 < s_minKeySizeInBits) || (issuerEntropy.Length * 8 > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid issuerEntropy size. issuerEntropy.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.", issuerEntropy.Length * 8, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(issuerEntropy)));

            if ((requestorEntropy.Length * 8 < s_minKeySizeInBits) || (requestorEntropy.Length * 8 > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid requestorEntropy size. requestorEntropy.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.", requestorEntropy.Length * 8, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(requestorEntropy)));

            int keySizeInBytes = ValidateKeySizeInBytes(keySizeInBits);

            // Final key
            byte[] key = new byte[keySizeInBytes];

            // The symmetric key generation chosen is http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1 per the WS-Trust specification is defined as follows:
            //   The key is computed using P_SHA1 from the TLS specification to generate a bit stream using two sets of entropy.
            //
            //   key = P_SHA1 (EntREQ, EntRES)
            //
            // where P_SHA1 is defined per http://www.ietf.org/rfc/rfc2246.txt 
            // and EntREQ is the entropy supplied by the requestor and EntRES 
            // is the entrophy supplied by the issuer.
            //
            // From http://www.faqs.org/rfcs/rfc2246.html:
            // 
            // 8<------------------------------------------------------------>8
            // First, we define a data expansion function, P_hash(secret, data)
            // which uses a single hash function to expand a secret and seed 
            // into an arbitrary quantity of output:
            // 
            // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
            //                        HMAC_hash(secret, A(2) + seed) +
            //                        HMAC_hash(secret, A(3) + seed) + ...
            //
            // Where + indicates concatenation.
            //
            // A() is defined as:
            //   A(0) = seed
            //   A(i) = HMAC_hash(secret, A(i-1))
            //
            // P_hash can be iterated as many times as is necessary to produce
            // the required quantity of data. For example, if P_SHA-1 was 
            // being used to create 64 bytes of data, it would have to be 
            // iterated 4 times (through A(4)), creating 80 bytes of output 
            // data; the last 16 bytes of the final iteration would then be 
            // discarded, leaving 64 bytes of output data.
            // 8<------------------------------------------------------------>8

            // Note that requestorEntrophy is considered the 'secret'.
            using (KeyedHashAlgorithm kha = new HMACSHA1(requestorEntropy))
            {
                byte[] a = issuerEntropy; // A(0), the 'seed'.
                byte[] b = new byte[kha.HashSize / 8 + a.Length]; // Buffer for A(i) + seed
                byte[] result = null;
                try
                {

                    for (int i = 0; i < keySizeInBytes;)
                    {
                        // Calculate A(i+1).                
                        kha.Initialize();
                        a = kha.ComputeHash(a);

                        // Calculate A(i) + seed
                        a.CopyTo(b, 0);
                        issuerEntropy.CopyTo(b, a.Length);
                        kha.Initialize();
                        result = kha.ComputeHash(b);

                        for (int j = 0; j < result.Length; j++)
                        {
                            if (i < keySizeInBytes)
                            {
                                key[i++] = result[j];
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
                catch
                {
                    Array.Clear(key, 0, key.Length);
                    throw;
                }
                finally
                {
                    if (result != null)
                    {
                        Array.Clear(result, 0, result.Length);
                    }

                    Array.Clear(b, 0, b.Length);

                    kha.Clear();
                }
            }

            return key;
        }

        internal static int ValidateKeySizeInBytes(int keySizeInBits)
        {
            int keySizeInBytes = keySizeInBits / 8;

            if (keySizeInBits <= 0)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("keySizeInBits is less than 0"));

            if (keySizeInBytes * 8 != keySizeInBits)
                throw LogHelper.LogExceptionMessage(new ArgumentException("keySizeInBits must be a multiple of 8"));

            return keySizeInBytes;
        }

        /// <summary>
        /// Generates a ramdon key material for receiverEntropy and uses that to create a combined-entropy key.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits.</param>
        /// <param name="senderEntropy">Requestor's entropy.</param>
        /// <param name="receiverEntropy">The issuer's entropy.</param>
        /// <returns>The computed symmetric key based on PSHA1 algorithm.</returns>
        /// <exception cref="ArgumentException">When keySizeInBits is not a whole number of bytes.</exception>
        internal static byte[] GenerateSymmetricKey(int keySizeInBits, byte[] senderEntropy, out byte[] receiverEntropy)
        {
            if (senderEntropy == null)
                throw LogHelper.LogArgumentNullException(nameof(senderEntropy));

            int keySizeInBytes = ValidateKeySizeInBytes(keySizeInBits);
            receiverEntropy = new byte[keySizeInBytes];
            _random.GetNonZeroBytes(receiverEntropy);
            return ComputeCombinedKey(senderEntropy, receiverEntropy, keySizeInBits);
        }

        /// <summary>
        /// Provides an integer-domain mathematical operation for 
        /// Ceiling( dividend / divisor ). 
        /// </summary>
        /// <param name="dividend"></param>
        /// <param name="divisor"></param>
        /// <returns></returns>
        internal static int CeilingDivide(int dividend, int divisor)
        {
            int remainder, quotient;

            remainder = dividend % divisor;
            quotient = dividend / divisor;

            if (remainder > 0)
            {
                quotient++;
            }

            return quotient;
        }

        internal static RandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (_random == null)
                    _random = new RNGCryptoServiceProvider();

                return _random;
            }
        }

        internal static byte[] GenerateDerivedKey(string algorithm, byte[] masterKey, byte[] label, byte[] nonce, int derivedKeySizeInBits, int position)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            return (new PshaDerivedKeyGenerator(masterKey)).ComputeCombinedKey(algorithm, label, nonce, derivedKeySizeInBits, position);
        }

        /// <summary>
        /// Fills buffer with random bytes.
        /// </summary>
        /// <param name="buffer"></param>
        public static void FillRandomBytes(byte[] buffer)
        {
            if (buffer == null)
                LogHelper.LogArgumentNullException(nameof(buffer));

            RandomNumberGenerator.GetBytes(buffer);
        }

        /// <summary>
        /// This generates the entropy using random number. This is usually used on the sending 
        /// side to generate the requestor's entropy.
        /// </summary>
        /// <param name="data">The array to fill with cryptographically strong random nonzero bytes.</param>
        internal static void GenerateRandomBytes(byte[] data)
        {
            RandomNumberGenerator.GetNonZeroBytes(data);
        }

        /// <summary>
        /// This method generates a random byte array used as entropy with the given size. 
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        internal static byte[] GenerateRandomBytes(int sizeInBits)
        {
            int sizeInBytes = sizeInBits / 8;
            if (sizeInBits <= 0)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(sizeInBits), nameof(sizeInBits)));

            if (sizeInBytes * 8 != sizeInBits)
                throw LogHelper.LogExceptionMessage(new ArgumentException("sizeInBits must be multiple of 8", nameof(sizeInBits)));

            byte[] data = new byte[sizeInBytes];
            GenerateRandomBytes(data);
            return data;
        }
    }
}
