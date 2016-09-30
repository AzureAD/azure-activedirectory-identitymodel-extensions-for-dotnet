using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens
{
    public class EncryptionResult
    {
        // CEK
        public byte[] Key { get; set; }

        public byte[] CipherText { get; set; }

        public byte[] InitialVector { get; set; }

        public byte[] AuthenticationTag { get; set; }
    }
}
