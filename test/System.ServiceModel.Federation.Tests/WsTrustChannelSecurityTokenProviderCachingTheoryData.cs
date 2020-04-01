using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class WsTrustChannelSecurityTokenProviderCachingTheoryData : TheoryDataBase
    {
        public bool CacheIssuedTokens { get; set; }
        public int IssuedTokenRenewalThresholdPercentage { get; set; }
        public TimeSpan MaxIssuedTokenCachingTime { get; set; }
    }
}
