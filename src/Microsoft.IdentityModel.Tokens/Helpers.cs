using System;

namespace Microsoft.IdentityModel.Tokens
{
    public static class Helpers
    {
        public static byte[] CloneByteArray(this byte[] src)
        {
            return (byte[])(src.Clone());
        }
    }
}