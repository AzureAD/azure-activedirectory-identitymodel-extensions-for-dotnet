using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens
{
    public class AuthenticatedEncryptionParameters
    {
        public byte[] Key { get; set; }
        public byte[] InitialVector { get; set; }
        public byte[] AuthenticationTag { get; set; }
    }
}
