using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Federation.Tests.Mocks;
using System.Threading;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using SecurityToken = System.IdentityModel.Tokens.SecurityToken;
using SymmetricSecurityKey = System.IdentityModel.Tokens.SymmetricSecurityKey;

namespace System.ServiceModel.Federation.Tests
{
    public class WSTrustChannelSecurityTokenProviderTests
    {
        private static byte[] TestEntropy1 { get; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        private static byte[] TestEntropy2 { get; } = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        private static byte[] TestEntropy3 { get; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        private static byte[] TestEntropy4 { get; } = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        [Theory, MemberData(nameof(CachingSettingsFromClientCredentialsTheoryData))]
        public void CachingSettingsAreInheritedFromClientCredentials(WsTrustChannelSecurityTokenProviderCachingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.CachingSettingsAreInheritedFromClientCredentials", theoryData);

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

        public static TheoryData<WsTrustChannelSecurityTokenProviderCachingTheoryData> CachingSettingsFromClientCredentialsTheoryData
        {
            get => new TheoryData<WsTrustChannelSecurityTokenProviderCachingTheoryData>
            {
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 80,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1)
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = true,
                    IssuedTokenRenewalThresholdPercentage = 100,
                    MaxIssuedTokenCachingTime = TimeSpan.MaxValue
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
                {
                    CacheIssuedTokens = false,
                    IssuedTokenRenewalThresholdPercentage = 0,
                    MaxIssuedTokenCachingTime = TimeSpan.FromDays(1),
                    ExpectedException = ExpectedException.ArgumentOutOfRangeException("value")
                },
                new WsTrustChannelSecurityTokenProviderCachingTheoryData
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

                // Confirm that no caching occurs when caching is disabled
                var provider5 = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement)
                {
                    CacheIssuedTokens = false
                };
                data.Add(new ProviderCachingTheoryData
                {
                    Provider1 = provider5,
                    Provider2 = provider5,
                    ShouldShareToken = false
                });

                // Confirm that tokens are not cached longer than MaxIssuedTokenCachingTime
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

        [Theory, MemberData(nameof(ProofTokenTheoryData))]
        public void ProofTokenGeneration(ProofTokenGenerationTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ProofToken", theoryData);

            try
            {
                SecurityTokenRequirement tokenRequirement = WSTrustTestHelpers.CreateSecurityRequirement(new BasicHttpBinding());
                var provider = new WSTrustChannelSecurityTokenProviderWithMockChannelFactory(tokenRequirement);
                provider.SetResponseSettings(theoryData.ResponseSettings);
                if (theoryData.RequestEntropy != null)
                {
                    provider.SetRequestEntropyAndKeySize(theoryData.RequestEntropy, theoryData.RequestKeySize);
                }

                GenericXmlSecurityToken token = provider.GetToken(TimeSpan.FromMinutes(1)) as GenericXmlSecurityToken;

                theoryData.ExpectedException.ProcessNoException(context);

                if (theoryData.ExpectedProofKey is null)
                {
                    IdentityComparer.AreIntsEqual(token.SecurityKeys.Count, 0, context);
                }
                else
                {
                    if (IdentityComparer.AreIntsEqual(token.SecurityKeys.Count, 1, context))
                    {
                        var key = token.SecurityKeys[0] as SymmetricSecurityKey;
                        IdentityComparer.AreBytesEqual(key.GetSymmetricKey(), theoryData.ExpectedProofKey, context);
                    }
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ProofTokenGenerationTheoryData> ProofTokenTheoryData
        {
            get => new TheoryData<ProofTokenGenerationTheoryData>
            {
                //new ProofTokenGenerationTheoryData
                //{
                //    // Bearer token scenario
                //    RequestEntropy = null,
                //    ResponseSettings = new MockResponseSettings
                //    {
                //        Entropy = null,
                //        ProofToken = null
                //    },
                //    ExpectedProofKey = null
                //},
                //new ProofTokenGenerationTheoryData
                //{
                //    // Client-supplied key material
                //    RequestEntropy = new Entropy(new BinarySecret(TestEntropy1)),
                //    ResponseSettings = new MockResponseSettings
                //    {
                //        Entropy = null,
                //        ProofToken = null
                //    },
                //    ExpectedProofKey = TestEntropy1
                //},
                //new ProofTokenGenerationTheoryData
                //{
                //    // Server-supplied key material
                //    ResponseSettings = new MockResponseSettings
                //    {
                //        Entropy = null,
                //        ProofToken = new RequestedProofToken(new BinarySecret(TestEntropy2))
                //    },
                //    ExpectedProofKey = TestEntropy2
                //},
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, default key size
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy2)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy1)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy1, TestEntropy2, 128)
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, key size from response
                    RequestKeySize = 512,
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy3)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy4)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1),
                        KeySizeInBits = 256
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy4, TestEntropy3, 256)
                },
                new ProofTokenGenerationTheoryData
                {
                    // Computed key, key size from request
                    RequestKeySize = 192,
                    RequestEntropy = new Entropy(new BinarySecret(TestEntropy1)),
                    ResponseSettings = new MockResponseSettings
                    {
                        Entropy = new Entropy(new BinarySecret(TestEntropy3)),
                        ProofToken = new RequestedProofToken(WsTrustKeyTypes.Trust13.PSHA1)
                    },
                    ExpectedProofKey = KeyGenerator.ComputeCombinedKey(TestEntropy3, TestEntropy1, 192)
                },
            };
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
                }
            };
        }
    }
}
