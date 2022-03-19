// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    ///
    /// </summary>
    public interface IClaimProvider
    {
        /// <summary>
        /// 
        /// </summary>
        IEnumerable<Claim> CreateClaims(string issuer);
    }
}
