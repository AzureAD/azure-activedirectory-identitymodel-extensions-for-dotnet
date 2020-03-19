using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Federation.Tests.Mocks;
using System.Threading;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace System.ServiceModel.Federation.Tests
{
    public class WSTrustChannelSecurityTokenProviderTests
    {

        [Theory, MemberData(nameof(CachingSettingsFromClientCredentialsTheoryData))]
        public void CachingSettingsAreInheritedFromClientCredentials(WsTrustChannelSecurityTokenProviderTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CachingSettingsAreInheritedFromClientCredentials", theoryData);

            try
            {
                var credentials = new WsTrustChannelClientCredentials()
                {
                    CacheIssuedTokens = theoryData.CacheIssuedTokens,
                    IssuedTokenRenewalThresholdPercentage = theoryData.IssuedTokenRenewalThresholdPercentage,
                    MaxIssuedTokenCachingTime = theoryData.MaxIssuedTokenCachingTime
                };

                SecurityTokenRequirement tokenRequirements = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
                var tokenProvider = credentials.CreateSecurityTokenManager().CreateSecurityTokenProvider(tokenRequirements) as WSTrustChannelSecurityTokenProvider;

                theoryData.ExpectedException.ProcessNoException(context);
                if (tokenProvider.CacheIssuedTokens != theoryData.CacheIssuedTokens)
                {
                    context.AddDiff($"Expected CacheIssuedTokens: {theoryData.CacheIssuedTokens}; actual CacheIssuedTokens: {tokenProvider.CacheIssuedTokens}");
                }
                if (tokenProvider.MaxIssuedTokenCachingTime != theoryData.MaxIssuedTokenCachingTime)
                {
                    context.AddDiff($"Expected MaxIssuedTokenCachingTime: {theoryData.MaxIssuedTokenCachingTime}; actual MaxIssuedTokenCachingTime: {tokenProvider.MaxIssuedTokenCachingTime}");
                }
                if (tokenProvider.IssuedTokenRenewalThresholdPercentage != theoryData.IssuedTokenRenewalThresholdPercentage)
                {
                    context.AddDiff($"Expected IssuedTokenRenewalThresholdPercentage: {theoryData.IssuedTokenRenewalThresholdPercentage}; actual IssuedTokenRenewalThresholdPercentage: {tokenProvider.IssuedTokenRenewalThresholdPercentage}");
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustChannelSecurityTokenProviderTheoryData> CachingSettingsFromClientCredentialsTheoryData
        {
            get => new TheoryData<WsTrustChannelSecurityTokenProviderTheoryData>
            {
                new WsTrustChannelSecurityTokenProviderTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 80,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1)
                },
                new WsTrustChannelSecurityTokenProviderTheoryData
                {
                    CacheIssuedTokens = true,
                    IssuedTokenRenewalThresholdPercentage = 100,
                    MaxIssuedTokenCachingTime = TimeSpan.MaxValue
                },
                new WsTrustChannelSecurityTokenProviderTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 0,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new WsTrustChannelSecurityTokenProviderTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 10,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(-1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                }
            };
        }

        [Theory, MemberData(nameof(ProviderCachingTheoryData))]
        public void ProviderCaching(ProviderCachingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ProviderCaching", theoryData);

            try
            {
                SecurityToken token1 = theoryData.Provider1.GetToken(TimeSpan.FromMinutes(1));
                Thread.Sleep(theoryData.WaitBetweenGetTokenCallsMS);
                SecurityToken token2 = theoryData.Provider2.GetToken(TimeSpan.FromMinutes(1));

                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(token1.Id.Equals(token2.Id), theoryData.ShouldShareToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ProviderCachingTheoryData> ProviderCachingTheoryData
        {
            get
            {
                var data = new TheoryData<ProviderCachingTheoryData>();
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());

                // Simple positive case
                var provider1 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider1,
                    ShouldShareToken = true
                });

                // Simple negative case
                var provider2 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider2,
                    ShouldShareToken = false
                });

                // Confirm that caches can be shared if contexts are the same
                var provider3 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    // Share cache and context
                    TestIssuedTokensCache = provider1.TestIssuedTokensCache,
                    TokenContext = provider1.TokenContext
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider3,
                    ShouldShareToken = true
                });

                // Confirm that different contexts will result in not re-using tokens
                var provider4 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    // Share cache but not context
                    TestIssuedTokensCache = provider1.TestIssuedTokensCache
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider1,
                    Provider2 = provider4,
                    ShouldShareToken = false
                });

                // Confirm that no caching occurs when caching is disabled
                var provider5 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                provider5.CacheIssuedTokens = false;
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider5,
                    Provider2 = provider5,
                    ShouldShareToken = false
                });

                // Confirm that tokens are cached longer than MaxIssuedTokenCachingTime
                var provider6 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(2)
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider6,
                    Provider2 = provider6,
                    WaitBetweenGetTokenCallsMS = 500,
                    ShouldShareToken = true
                });
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider6,
                    Provider2 = provider6,
                    WaitBetweenGetTokenCallsMS = 2500,
                    ShouldShareToken = false
                });

                return data;
            }
        }

        [Theory, MemberData(nameof(ErrorConditionTheoryData))]
        public void ExceptionsAreThrownForErrorConditions(ErrorConditionTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ExceptionsAreThrownForErrorConditions", theoryData);

            try
            {
                // Create provider
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
                var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);

                theoryData.Action(provider);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ErrorConditionTheoryData> ErrorConditionTheoryData
        {
            get => new TheoryData<ErrorConditionTheoryData>
            {
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.MaxIssuedTokenCachingTime = TimeSpan.Zero,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value"),
                    First = true
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.MaxIssuedTokenCachingTime = TimeSpan.FromSeconds(-1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = 0,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = -1,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => p.IssuedTokenRenewalThresholdPercentage = 101,
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new ErrorConditionTheoryData
                {
                    Action = (WSTrustChannelSecurityTokenProvider p) => (p as WSTrustChannelSecurityTokenProviderWithMockChannelFactory).TestIssuedTokensCache = null,
                    ExpectedException = ExpectedException.ArgumentNullException("value")
                }
            };
        }
    }
}
