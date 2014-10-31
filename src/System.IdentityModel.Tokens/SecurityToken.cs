//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    public abstract class SecurityToken
    {
        public abstract string Id { get; }
        public abstract SecurityKey SecurityKey { get; }
        public abstract DateTime ValidFrom { get; }
        public abstract DateTime ValidTo { get; }
    }
}
