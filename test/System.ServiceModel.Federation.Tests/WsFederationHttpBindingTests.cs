// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace System.ServiceModel.Federation.Tests
{
    public class WsFederationHttpBindingTests
    {
        [Theory, MemberData(nameof(SecurityKeyTheoryData))]
        public void BindingPropertiesPropagated(WsFederationHttpBindingTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.BindingPropertiesPropagated", theoryData);

            try
            {
                var wsTrustTokenParameters = new WsTrustTokenParameters
                {
                    IssuerAddress = new EndpointAddress(new Uri("https://localhost")),
                    IssuerBinding = new WSHttpBinding(SecurityMode.Transport),
                    KeyType = theoryData.KeyType,
                    RequestContext = theoryData.RequestContext,
                    Target = "https://localhost",
                    TokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
                    EstablishSecurityContext = false
                };

                var binding = new WsFederationHttpBinding(wsTrustTokenParameters);
                var provider = GetProviderForBinding(binding) as WsTrustChannelSecurityTokenProvider;

                IssuedSecurityTokenParameters issuedSecurityTokenParameters = provider?.SecurityTokenRequirement.GetProperty<IssuedSecurityTokenParameters>("http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters");

                theoryData.ExpectedException.ProcessNoException(context);
                if (issuedSecurityTokenParameters.KeyType != theoryData.KeyType)
                {
                    context.AddDiff($"Expected KeyType: {theoryData.KeyType}; actual KeyType: {issuedSecurityTokenParameters.KeyType}");
                }

                // Confirm that if a request context was specified, it was used. Otherwise, a random GUID is used
                // as the context.
                if (string.IsNullOrEmpty(theoryData.RequestContext))
                {
                    if (!Guid.TryParse(provider.RequestContext, out _))
                    {
                        context.AddDiff($"Expected a random guid Context; actual Context: {provider.RequestContext}");
                    }
                }
                else
                {
                    if (!string.Equals(provider.RequestContext, theoryData.RequestContext))
                    {
                        context.AddDiff($"Expected Context: {theoryData.RequestContext}; actual Context: {provider.RequestContext}");
                    }
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsFederationHttpBindingTheoryData> SecurityKeyTheoryData
        {
            get => new TheoryData<WsFederationHttpBindingTheoryData>
            {
                new WsFederationHttpBindingTheoryData
                {
                    First = true,
                    KeyType = SecurityKeyType.AsymmetricKey,
                    RequestContext = "DummyContext",
                    TestId="Test1"
                },
                new WsFederationHttpBindingTheoryData
                {
                    KeyType = SecurityKeyType.AsymmetricKey,
                    RequestContext = null,
                    TestId="Test2"
                },
                new WsFederationHttpBindingTheoryData
                {
                    KeyType = SecurityKeyType.SymmetricKey,
                    RequestContext = null,
                    TestId="Test3"
                },
                new WsFederationHttpBindingTheoryData
                {
                    KeyType = SecurityKeyType.BearerKey,
                    RequestContext = null,
                    TestId="Test4"
                },
                new WsFederationHttpBindingTheoryData
                {
                    KeyType = SecurityKeyType.AsymmetricKey,
                    RequestContext = string.Empty,
                    TestId="Test5"
                }
            };
        }

        public static SecurityTokenProvider GetProviderForBinding(Binding binding)
        {
            var factory = new ChannelFactory<IRequestChannel>(binding, new EndpointAddress(new Uri("https://localhost")));
            IRequestChannel channel = factory.CreateChannel();
            channel.Open();

            // TODO: This is not a great way to test since private reflection is fragile.
            // This allows for quick initial testing but should be replaced with a more robust testing approach
            // in the future (perhaps overriding the WsFederationHttpBinding's transport element to intercept requests)
            var serviceChannel = ReflectionHelpers.CallInternalMethod(channel, "GetServiceChannel");
            var innerChannel = ReflectionHelpers.GetInternalProperty(serviceChannel, "InnerChannel");
            var securityProtocol = ReflectionHelpers.GetInternalProperty(innerChannel, "SecurityProtocol");
            var providerSpecifications = ReflectionHelpers.GetInternalProperty(securityProtocol, "ChannelSupportingTokenProviderSpecification");
            var specification = ReflectionHelpers.CallInternalMethod(providerSpecifications, "get_Item", 0);
            var provider = ReflectionHelpers.GetInternalProperty(specification, "TokenProvider");

            return provider as SecurityTokenProvider;
        }
    }
}
