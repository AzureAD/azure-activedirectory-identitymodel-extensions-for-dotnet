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

namespace Microsoft.IdentityModel.Tokens
{
    public class SymmetricSecurityKey : SecurityKey
    {
        int _keySize;
        byte[] _key;

        public SymmetricSecurityKey(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (key.Length == 0)
            {
                throw new ArgumentException("SR.GetString(SR.SymmetricKeyLengthTooShort, symmetricKey.Length))");
            }

            _key = key.CloneByteArray();
            _keySize = _key.Length * 8;
        }

        public override int KeySize
        {
            get { return _keySize; }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            var factory = this.CryptoProviderFactory ?? CryptoProviderFactory.Default;

            if (verifyOnly)
                return factory.CreateForVerifying(this, algorithm);
            else
                return factory.CreateForSigning(this, algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                return false;

            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.HmacSha512:
                    return true;

                default:
                    return false;
            }
        }

        public virtual byte[] Key
        {
            get { return _key.CloneByteArray(); }
        }

        //public abstract byte[] GenerateDerivedKey(string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset);
        //public abstract ICryptoTransform GetDecryptionTransform(string algorithm, byte[] iv);
        //public abstract ICryptoTransform GetEncryptionTransform(string algorithm, byte[] iv);
        //public abstract int GetIVSize(string algorithm);
        //public abstract KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm);
        //public abstract SymmetricAlgorithm GetSymmetricAlgorithm(string algorithm);
        //public abstract byte[] GetSymmetricKey();
    }
}
