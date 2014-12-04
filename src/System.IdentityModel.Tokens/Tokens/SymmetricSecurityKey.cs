//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Security.Cryptography;

    public class SymmetricSecurityKey : SecurityKey
    {
        int keySize;
        byte[] symmetricKey;

        public SymmetricSecurityKey(byte[] symmetricKey)
            : this(symmetricKey, true)
        {
        }

        public SymmetricSecurityKey(byte[] symmetricKey, bool cloneBuffer)
        {
            if (symmetricKey == null)
            {
                throw new ArgumentNullException("symmetricKey");
            }

            if (symmetricKey.Length == 0)
            {
                throw new ArgumentException("SR.GetString(SR.SymmetricKeyLengthTooShort, symmetricKey.Length))");
            }
            this.keySize = symmetricKey.Length * 8;

            if (cloneBuffer)
            {
                this.symmetricKey = new byte[symmetricKey.Length];
                Buffer.BlockCopy(symmetricKey, 0, this.symmetricKey, 0, symmetricKey.Length);
            }
            else
            {
                this.symmetricKey = symmetricKey;
            }
        }

        public override int KeySize
        {
            get { return this.keySize; }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm)
        {
            return null;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return false;
        }


        public virtual KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm)
        {
            return null;
        }

        public virtual byte[] GetSymmetricKey()
        {
            return this.symmetricKey;
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
