using System;
using System.Collections.Generic;
using System.Text;
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
