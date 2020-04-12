// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class ProviderCachingTheoryData : TheoryDataBase
    {
        public WSTrustChannelSecurityTokenProvider Provider1 { get; set; }

        public WSTrustChannelSecurityTokenProvider Provider2 { get; set; }

        public int WaitBetweenGetTokenCallsMS { get; set; }

        public bool ShouldShareToken { get; set; }
    }
}
