using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Text;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace System.ServiceModel.Federation.Tests
{
    public class WSTrustChannelSecurityTokenProviderTests
    {

        [Fact]
        public void CachingSettingsAreInheritedFromClientCredentials()
        {
            // Initialize provider
            var credentials = new WsTrustChannelClientCredentials()
            {
                CacheIssuedTokens = false,
                IssuedTokenRenewalThresholdPercentage = 80,
                MaxIssuedTokenCachingTime = TimeSpan.FromDays(1)
            };

            var tokenRequirements = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());

            var tokenProvider = credentials.CreateSecurityTokenManager().CreateSecurityTokenProvider(tokenRequirements) as WSTrustChannelSecurityTokenProvider;

            // Confirm initial settings are propagated
            Assert.False(tokenProvider.CacheIssuedTokens);
            Assert.Equal(80, tokenProvider.IssuedTokenRenewalThresholdPercentage);
            Assert.Equal(TimeSpan.FromDays(1), tokenProvider.MaxIssuedTokenCachingTime);

            // Change client credential settings
            credentials.CacheIssuedTokens = true;
            credentials.IssuedTokenRenewalThresholdPercentage = 1;
            credentials.MaxIssuedTokenCachingTime = TimeSpan.MaxValue;
            tokenProvider = credentials.CreateSecurityTokenManager().CreateSecurityTokenProvider(tokenRequirements) as WSTrustChannelSecurityTokenProvider;

            // Confirm updated settings are propagated
            Assert.True(tokenProvider.CacheIssuedTokens);
            Assert.Equal(1, tokenProvider.IssuedTokenRenewalThresholdPercentage);
            Assert.Equal(TimeSpan.MaxValue, tokenProvider.MaxIssuedTokenCachingTime);
        }
    }
}
