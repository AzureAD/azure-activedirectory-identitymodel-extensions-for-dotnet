// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Selectors;
using System.ServiceModel.Description;

namespace System.ServiceModel.Federation
{
    /// <summary>
    /// These client credentials class that will serve up a SecurityTokenManager that will use a TrustChannel to get a token from an STS
    /// </summary>
    public class WsTrustChannelClientCredentials : ClientCredentials
    {
        private TimeSpan _maxIssuedTokenCachingTime = WSTrustChannelSecurityTokenProvider.DefaultMaxIssuedTokenCachingTime;
        private int _issuedTokenRenewalThresholdPercentage = WSTrustChannelSecurityTokenProvider.DefaultIssuedTokenRenewalThresholdPercentage;

        /// <summary>
        /// Default constructor
        /// </summary>
        public WsTrustChannelClientCredentials()
            : base()
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            //SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The WSTrustChannelClientCredentials to create a copy of</param>
        protected WsTrustChannelClientCredentials(WsTrustChannelClientCredentials other)
            : base(other)
        {
        }

        /// <summary>
        /// The context to use in outgoing WsTrustRequests. Useful for correlation WSTrust actions.
        /// </summary>
        internal string RequestContext { get; set; }

        /// <summary>
        /// Gets or sets whether issued tokens should be cached and reused within their expiry periods.
        /// </summary>
        public bool CacheIssuedTokens { get; set; } = WSTrustChannelSecurityTokenProvider.DefaultCacheIssuedTokens;

        /// <summary>
        /// Gets or sets the maximum time an issued token will be cached before renewing it.
        /// </summary>
        public TimeSpan MaxIssuedTokenCachingTime
        {
            get => _maxIssuedTokenCachingTime;
            set => _maxIssuedTokenCachingTime = value <= TimeSpan.Zero
                ? throw new ArgumentOutOfRangeException(nameof(value), "TimeSpan must be greater than TimeSpan.Zero.") // TODO - Get exception messages from resources
                : value;
        }

        /// <summary>
        /// Gets or sets the percentage of the issued token's lifetime at which it should be renewed instead of cached.
        /// </summary>
        public int IssuedTokenRenewalThresholdPercentage
        {
            get => _issuedTokenRenewalThresholdPercentage;
            set => _issuedTokenRenewalThresholdPercentage = (value <= 0 || value > 100)
                ? throw new ArgumentOutOfRangeException(nameof(value), "Issued token renewal threshold percentage must be greater than or equal to 1 and less than or equal to 100.")
                : value;
        }

        protected override ClientCredentials CloneCore()
        {
            return new WsTrustChannelClientCredentials(this);
        }

        /// <summary>
        /// Extensibility point for serving up the WSTrustChannelSecurityTokenManager
        /// </summary>
        /// <returns>WSTrustChannelSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new WsTrustChannelSecurityTokenManager(this);
        }
    }
}
