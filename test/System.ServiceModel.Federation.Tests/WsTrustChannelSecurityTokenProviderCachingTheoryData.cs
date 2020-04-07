// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

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
