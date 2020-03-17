using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Federation.Tests.Mocks;
using System.Threading;
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

            SecurityTokenRequirement tokenRequirements = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());

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

        [Fact]
        public void CachedResponsesAreReused()
        {
            // Create providers
            SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
            var provider1 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
            var provider2 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
            {
                // Share context
                TokenContext = provider1.TokenContext
            };

            // Get initial tokens
            SecurityToken token1FromProvider1 = provider1.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token1FromProvider2 = provider2.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token2FromProvider1 = provider1.GetToken(TimeSpan.FromMinutes(1));

            // Confirm that tokens are shared within a provider but not between providers, by default
            Assert.Equal(token1FromProvider1.Id, token2FromProvider1.Id);
            Assert.NotEqual(token1FromProvider1.Id, token1FromProvider2.Id);
        }

        [Fact]
        public void CachesCanBeShared()
        {
            // Create providers
            SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
            var provider1 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
            var provider2 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
            {
                // Share cache
                TestIssuedTokensCache = provider1.TestIssuedTokensCache
            };

            // Get initial tokens
            SecurityToken token1FromProvider1 = provider1.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token1FromProvider2 = provider2.GetToken(TimeSpan.FromMinutes(1));

            // Share context
            provider2.TokenContext = provider1.TokenContext;

            // Get updated tokens
            SecurityToken token2FromProvider1 = provider1.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token2FromProvider2 = provider2.GetToken(TimeSpan.FromMinutes(1));

            // Confirm that tokens are re-used between providers when using both a shared cache and shared context
            Assert.Equal(token1FromProvider1.Id, token2FromProvider1.Id);
            Assert.Equal(token1FromProvider1.Id, token2FromProvider2.Id);
            Assert.NotEqual(token1FromProvider1.Id, token1FromProvider2.Id);
            Assert.NotEqual(token1FromProvider2.Id, token2FromProvider2.Id);
        }

        [Fact]
        public void NoCachingWhenCachingDisabled()
        {
            // Create provider
            SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
            var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
            {
                // Disable caching
                CacheIssuedTokens = false
            };

            // Get tokens
            SecurityToken token1 = provider.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token2 = provider.GetToken(TimeSpan.FromMinutes(1));

            // Confirm that tokens are no re-used
            Assert.NotEqual(token1.Id, token2.Id);
        }

        [Fact]
        public void ConfirmResponsesNotCachedLongerThanMaxCacheTime()
        {
            // Create provider
            SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
            var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
            {
                // Reduce max caching time
                MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(3)
            };

            // Get tokens
            SecurityToken token1 = provider.GetToken(TimeSpan.FromMinutes(1));
            Thread.Sleep(2000);
            SecurityToken token2 = provider.GetToken(TimeSpan.FromMinutes(1));
            Thread.Sleep(2000);
            SecurityToken token3 = provider.GetToken(TimeSpan.FromMinutes(1));
            SecurityToken token4 = provider.GetToken(TimeSpan.FromMinutes(1));

            // Confirm that tokens are cached only up until max caching time
            Assert.Equal(token1.Id, token2.Id);
            Assert.Equal(token3.Id, token4.Id);
            Assert.NotEqual(token1.Id, token3.Id);
        }

        [Fact]
        public void ExceptionsAreThrownForErrorConditions()
        {
            // Create provider
            SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
            var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);

            Assert.Throws<ArgumentOutOfRangeException>(() => provider.MaxIssuedTokenCachingTime = TimeSpan.Zero);
            Assert.Throws<ArgumentOutOfRangeException>(() => provider.MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => provider.IssuedTokenRenewalThresholdPercentage = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => provider.IssuedTokenRenewalThresholdPercentage = -1);
            Assert.Throws<ArgumentOutOfRangeException>(() => provider.IssuedTokenRenewalThresholdPercentage = 101);
            Assert.Throws<ArgumentNullException>(() => provider.TestIssuedTokensCache = null);
        }
    }
}
