// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Selectors;
using System.Reflection;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    /// <summary>
    /// Test class that overrides WSTrustChannelSecurityTokenProvider's CreateChannelFactory method
    /// to allow testing WSTrustChannelSecurityTokenProvider without actually sending any WCF messages.
    /// </summary>
    class WSTrustChannelSecurityTokenProviderWithMockChannelFactory : WSTrustChannelSecurityTokenProvider
    {
        public Entropy RequestEntropy { get; set; }
        public int? RequestKeySizeInBits { get; set; }

        public WSTrustChannelSecurityTokenProviderWithMockChannelFactory(SecurityTokenRequirement tokenRequirement, string requestContext) :
            base(tokenRequirement, requestContext)
        { }

        public WSTrustChannelSecurityTokenProviderWithMockChannelFactory(SecurityTokenRequirement tokenRequirement) :
            base(tokenRequirement)
        { }

        // Override channel factory creation with a mock channel factory so that it's possible to test WSTrustChannelSecurityTokenProvider
        // without actually making requests to an STS for tokens.
        protected override ChannelFactory<IRequestChannel> CreateChannelFactory() =>
            new MockRequestChannelFactory();

        protected override WsTrustRequest CreateWsTrustRequest()
        {
            WsTrustRequest request = base.CreateWsTrustRequest();

            if (RequestEntropy != null)
            {
                request.Entropy = RequestEntropy;
            }

            if (RequestKeySizeInBits.HasValue)
            {
                request.KeySizeInBits = RequestKeySizeInBits;
            }

            return request;
        }

        public void SetResponseSettings(MockResponseSettings responseSettings)
        {
            var channelFactory = typeof(WSTrustChannelSecurityTokenProvider)
                .GetField("_channelFactory", BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(this) as MockRequestChannelFactory;
            channelFactory.ResponseSettings = responseSettings;
        }
    }
}
