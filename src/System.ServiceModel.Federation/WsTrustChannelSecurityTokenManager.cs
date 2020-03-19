// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Selectors;

namespace System.ServiceModel.Federation
{
    /// <summary>
    /// Returns a WSTrustChannelSecurityTokenProvider to obtain token Saml
    /// </summary>
    public class WsTrustChannelSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        public WsTrustChannelSecurityTokenManager(WsTrustChannelClientCredentials clientCredentials)
            : base(clientCredentials)
        { }

        /// <summary>
        /// Make use of this extensibility point for returning a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
        /// </summary>
        /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
        /// <returns>The appropriate SecurityTokenProvider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            // If token requirement matches SAML token return the custom SAML token provider
            // that performs custom work to serve up the token
            var tokenProvider = (ClientCredentials is WsTrustChannelClientCredentials wsTrustChannelClientCredentials) ?
                new WSTrustChannelSecurityTokenProvider(tokenRequirement, wsTrustChannelClientCredentials.RequestContext)
                {
                    CacheIssuedTokens = wsTrustChannelClientCredentials.CacheIssuedTokens,
                    MaxIssuedTokenCachingTime = wsTrustChannelClientCredentials.MaxIssuedTokenCachingTime,
                    IssuedTokenRenewalThresholdPercentage = wsTrustChannelClientCredentials.IssuedTokenRenewalThresholdPercentage
                }
                : new WSTrustChannelSecurityTokenProvider(tokenRequirement);

            return tokenProvider;
        }
    }
}
