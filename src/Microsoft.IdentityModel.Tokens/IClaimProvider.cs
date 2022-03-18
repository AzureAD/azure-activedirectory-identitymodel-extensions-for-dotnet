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
        IEnumerable<Claim> Claims{ get; }
    }
}
