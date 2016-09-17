using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens
{
    public abstract class EncryptionProvider
    {
        public abstract EncryptionResult Encrypt(byte[] plaintext);

        public abstract byte[] Decrypt(byte[] ciphertext);
    }
}
