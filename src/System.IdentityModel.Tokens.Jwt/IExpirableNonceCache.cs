
namespace System.IdentityModel.Tokens
{
    // TODO - just added interface without any testing to get idea of how it fits
    /// <summary>
    /// Interface
    /// </summary>
    public interface IExpirableNonceCache
    {
        /// <summary>
        /// Try to add nonce
        /// </summary>
        /// <param name="nonce"></param>
        /// <param name="expiresAt"></param>
        /// <returns></returns>
        bool TryAdd(string nonce, DateTime expiresAt);

        /// <summary>
        /// Try to find nonce
        /// </summary>
        /// <param name="nonce"></param>
        /// <returns></returns>
        bool TryFind(string nonce);

        /// <summary>
        /// Try to Remove nonce
        /// </summary>
        /// <param name="nonce"></param>
        /// <returns></returns>
        bool TryRemove(string nonce);
    }
}
