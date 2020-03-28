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

// TODO - performance
namespace Microsoft.IdentityModel.Tokens
{
    internal class PshaDerivedKeyGenerator
    {
        static int s_minKeySizeInBits = 16 * 8; // 16 Bytes - 128 bits.
        static int s_maxKeySizeInBits = (16 * 1024) * 8; // 16 K

        private byte[] _masterKey;

        public PshaDerivedKeyGenerator(byte[] masterKey)
        {
            if (masterKey == null)
                throw LogHelper.LogArgumentNullException(nameof(masterKey));

            if ((masterKey.Length * 8 < s_minKeySizeInBits) || (masterKey.Length * 8 > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid masterKey size. masterKey.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.", masterKey.Length * 8, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(masterKey)));

            _masterKey = new byte[masterKey.Length];
            masterKey.CopyTo(_masterKey, 0);
        }

        public byte[] ComputeCombinedKey(string algorithm, byte[] label, byte[] nonce, int keySizeInBits, int position)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (nonce == null)
                throw LogHelper.LogArgumentNullException(nameof(nonce));

            // Do a sanity check here. We don't want to allow invalid keys or keys that are too large.
            if ((keySizeInBits < s_minKeySizeInBits) || (keySizeInBits > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid key size. Key size requested: '{0}', must be larger than '{1}' and smaller than '{2}'.", keySizeInBits, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(keySizeInBits)));

            if ((nonce.Length * 8 < s_minKeySizeInBits) || (nonce.Length * 8 > s_maxKeySizeInBits))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant("Invalid nonce size. nonce.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.", nonce.Length * 8, s_minKeySizeInBits, s_maxKeySizeInBits), nameof(nonce)));

            return (new PshaKeyGenerator(_masterKey, label, nonce).GetDerivedKey(algorithm, keySizeInBits, position));
        }

        // private class to do the real work, create new instance for each call
        // Note: Though named ManagedPsha1, this works for both fips and non-fips compliance
        private class PshaKeyGenerator
        {
            private byte[] _aValue;
            private byte[] _buffer;
            private byte[] _chunk;
            private int _index;
            private int _position;
            private byte[] _masterKey;
            private byte[] _seed;

            // assume arguments are already validated
            internal PshaKeyGenerator(byte[] masterKey, byte[] label, byte[] seed)
            {
                if (label != null)
                {
                    _seed = new byte[seed.Length + label.Length];
                    label.CopyTo(_seed, 0);
                    seed.CopyTo(_seed, label.Length);
                }
                else
                {
                    _seed = new byte[seed.Length];
                    seed.CopyTo(_seed, 0);
                }

                _aValue = _seed;
                _chunk = new byte[0];
                _index = 0;
                _position = 0;
                _masterKey = masterKey;
            }

            internal byte[] GetDerivedKey(string algorithm, int derivedKeySize, int position)
            {
                using (KeyedHashAlgorithm hmac = CryptoProviderFactory.Default.CreateKeyedHashAlgorithm(_masterKey, algorithm))
                {
                    _buffer = new byte[hmac.HashSize / 8 + _seed.Length];

                    // Seek to the desired position in the pseudo-random stream.
                    while (_position < position)
                    {
                        GetByte(hmac);
                    }

                    int sizeInBytes = derivedKeySize / 8;
                    byte[] derivedKey = new byte[sizeInBytes];
                    for (int i = 0; i < sizeInBytes; i++)
                        derivedKey[i] = GetByte(hmac);

                    return derivedKey;
                }
            }

            private byte GetByte(KeyedHashAlgorithm hmac)
            {
                if (_index >= _chunk.Length)
                {
                    // Calculate A(i) = HMAC_SHA1(secret, A(i-1)).
                    hmac.Initialize();
                    _aValue = hmac.ComputeHash(_aValue);

                    // Calculate P_SHA1(secret, seed)[j] = HMAC_SHA1(secret, A(j+1) || seed).
                    _aValue.CopyTo(_buffer, 0);
                    _seed.CopyTo(_buffer, _aValue.Length);
                    hmac.Initialize();
                    _chunk = hmac.ComputeHash(_buffer);
                    _index = 0;
                }

                _position++;
                return _chunk[_index++];
            }
        }
    }
}
