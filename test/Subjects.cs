//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    public static class Subjects
    {
        public static ClaimsIdentity Simple( string issuer, string originalIssuer )
        {
            return new ClaimsIdentity( ClaimSets.Simple( issuer, originalIssuer ) );
        }
    }
}
