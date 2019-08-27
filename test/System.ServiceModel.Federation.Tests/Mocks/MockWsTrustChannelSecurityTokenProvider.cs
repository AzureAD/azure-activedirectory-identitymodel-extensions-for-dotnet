// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    /// <summary>
    /// Test class that overrides WSTrustChannelSecurityTokenProvider's CreateChannelFactory method
    /// to allow testing WSTrustChannelSecurityTokenProvider without actually sending any WCF messages.
    /// </summary>
    class MockWsTrustChannelSecurityTokenProvider : WsTrustChannelSecurityTokenProvider
    {
        public Entropy RequestEntropy { get; set; }

        public int? RequestKeySizeInBits { get; set; }

        private MockRequestChannelFactory _mockRequestChannelFactory = new MockRequestChannelFactory();

        public MockWsTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement) :
            base(tokenRequirement)
        { }

        // Override channel factory creation with a mock channel factory so that it's possible to test WSTrustChannelSecurityTokenProvider
        // without actually making requests to an STS for tokens.
        internal override ChannelFactory<IRequestChannel> ChannelFactory => _mockRequestChannelFactory;

        protected override WsTrustRequest CreateWsTrustRequest()
        {
            WsTrustRequest request = base.CreateWsTrustRequest();

            if (RequestEntropy != null)
                request.Entropy = RequestEntropy;

            if (RequestKeySizeInBits.HasValue)
                request.KeySizeInBits = RequestKeySizeInBits;

            return request;
        }

        public WsTrustRequest GetWsTrustRequest() => CreateWsTrustRequest();

        public void SetResponseSettings(MockResponseSettings responseSettings)
        {
            var channelFactory = ChannelFactory as MockRequestChannelFactory;
            channelFactory.ResponseSettings = responseSettings;
        }
    }
}
