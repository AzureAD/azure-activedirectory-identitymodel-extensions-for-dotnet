namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// 
    /// </summary>
    public interface IJsonClaimSet : IClaimSet
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="claim"></param>
        /// <param name="claimValue"></param>
        /// <returns></returns>
        bool TryGetPayloadValue<T>(string claim, out T claimValue);

        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="claim"></param>
        /// <param name="claimValue"></param>
        /// <returns></returns>
        bool TryGetHeaderValue<T>(string claim, out T claimValue);
    }
}
