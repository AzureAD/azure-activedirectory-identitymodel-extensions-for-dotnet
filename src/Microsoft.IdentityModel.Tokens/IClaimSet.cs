using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// 
    /// </summary>
    public interface IClaimSet
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="claim"></param>
        /// <param name="claimValue"></param>
        /// <returns></returns>
        bool TryGetValue<T> (string claim, out T claimValue);
    }
}
