//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    public abstract class SecurityKey
    {
        public abstract int KeySize { get; }
        public string KeyId { get; set; }
        public abstract bool IsSupportedAlgorithm(string algorithm);
    }
}
