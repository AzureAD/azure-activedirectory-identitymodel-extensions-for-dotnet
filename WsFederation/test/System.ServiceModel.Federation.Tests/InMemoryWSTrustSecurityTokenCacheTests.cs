using System.Collections.Generic;
using System.ServiceModel.Caching;
using System.Threading.Tasks;
using Xunit;

namespace System.ServiceModel.Federation.Tests
{
    public class InMemoryWSTrustSecurityTokenCacheTests
    {
        [Fact]
        public void SetAndGetTokens()
        {
            var cache = new InMemorySecurityTokenResponseCache<string, string>(EqualityComparer<string>.Default);

            string token1 = "1T";
            string token2 = "2T";
            string token3 = "3T";
            string updatedToken = "UT";

            cache.CacheSecurityTokenResponse("Token1", token1);
            cache.CacheSecurityTokenResponse("Token2", token2);
            cache.CacheSecurityTokenResponse("Token3", token3);

            Assert.Equal(token1, cache.GetSecurityTokenResponse("Token1"));
            Assert.Equal(token2, cache.GetSecurityTokenResponse("Token2"));
            Assert.Equal(token3, cache.GetSecurityTokenResponse("Token3"));
            Assert.Null(cache.GetSecurityTokenResponse("Token4"));

            Assert.True(cache.RemoveSecurityTokenResponse(token2));
            Assert.False(cache.RemoveSecurityTokenResponse(updatedToken));
            Assert.True(cache.RemoveSecurityTokenResponseByKey("Token3"));
            Assert.False(cache.RemoveSecurityTokenResponseByKey("token4"));

            Assert.Equal(token1, cache.GetSecurityTokenResponse("Token1"));
            Assert.Null(cache.GetSecurityTokenResponse("Token2"));
            Assert.Null(cache.GetSecurityTokenResponse("Token3"));

            cache.CacheSecurityTokenResponse("Token1", updatedToken);
            Assert.Equal(updatedToken, cache.GetSecurityTokenResponse("Token1"));
        }

        [Fact]
        public async Task SetAndGetTokensAsync()
        {
            var cache = new InMemorySecurityTokenResponseCache<string, string>(EqualityComparer<string>.Default);

            string token1 = "1T";
            string token2 = "2T";
            string token3 = "3T";
            string updatedToken = "UT";

            await cache.CacheSecurityTokenResponseAsync("Token1", token1);
            await cache.CacheSecurityTokenResponseAsync("Token2", token2);
            await cache.CacheSecurityTokenResponseAsync("Token3", token3);

            Assert.Equal(token1, await cache.GetSecurityTokenResponseAsync("Token1"));
            Assert.Equal(token2, await cache.GetSecurityTokenResponseAsync("Token2"));
            Assert.Equal(token3, await cache.GetSecurityTokenResponseAsync("Token3"));
            Assert.Null(await cache.GetSecurityTokenResponseAsync("Token4"));

            Assert.True(await cache.RemoveSecurityTokenResponseAsync(token2));
            Assert.False(await cache.RemoveSecurityTokenResponseAsync(updatedToken));
            Assert.True(await cache.RemoveSecurityTokenResponseByKeyAsync("Token3"));
            Assert.False(await cache.RemoveSecurityTokenResponseByKeyAsync("token4"));

            Assert.Equal(token1, await cache.GetSecurityTokenResponseAsync("Token1"));
            Assert.Null(await cache.GetSecurityTokenResponseAsync("Token2"));
            Assert.Null(await cache.GetSecurityTokenResponseAsync("Token3"));

            await cache.CacheSecurityTokenResponseAsync("Token1", updatedToken);
            Assert.Equal(updatedToken, await cache.GetSecurityTokenResponseAsync("Token1"));
        }

        [Fact]
        public void ExceptionsThrownForErrorConditions()
        {
            var cache = new InMemorySecurityTokenResponseCache<string, string>(EqualityComparer<string>.Default);

            Assert.Throws<ArgumentNullException>(() => cache.CacheSecurityTokenResponse("Token1", null));
            Assert.ThrowsAsync<ArgumentNullException>(() => cache.CacheSecurityTokenResponseAsync("Token1", null));
        }
    }
}
