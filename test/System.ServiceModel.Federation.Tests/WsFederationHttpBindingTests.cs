using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
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
            var context = TestUtilities.WriteHeader($"{this}.SecurityKeyTypePropagated", theoryData);

            try
            {
                var issuedTokenParameters = new IssuedTokenParameters
                {
                    IssuerAddress = new EndpointAddress(new Uri("https://localhost")),
                    IssuerBinding = new WSHttpBinding(SecurityMode.Transport),
                    SecurityKey = theoryData.IssuedTokenParametersSecurityKey,
                    Target = "https://localhost",
                    TokenType = Saml2Constants.OasisWssSaml2TokenProfile11
                };

                var binding = new WsFederationHttpBinding(issuedTokenParameters)
                {
                    WSTrustContext = theoryData.RequestContext
                };
                var provider = GetProviderForBinding(binding) as WSTrustChannelSecurityTokenProvider;

                IssuedSecurityTokenParameters issuedSecurityTokenParameters = provider?.SecurityTokenRequirement.GetProperty<IssuedSecurityTokenParameters>("http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters");

                theoryData.ExpectedException.ProcessNoException(context);
                if (issuedSecurityTokenParameters.KeyType != theoryData.IssuedSecurityTokenParametersKeyType)
                {
                    context.AddDiff($"Expected KeyType: {theoryData.IssuedSecurityTokenParametersKeyType}; actual KeyType: {issuedSecurityTokenParameters.KeyType}");
                }

                if (theoryData.RequestContext != null)
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
                    IssuedTokenParametersSecurityKey = KeyingMaterial.RsaSecurityKey_1024,
                    IssuedSecurityTokenParametersKeyType = System.IdentityModel.Tokens.SecurityKeyType.AsymmetricKey,
                    RequestContext = "DummyContext"
                },
                new WsFederationHttpBindingTheoryData
                {
                    First = true,
                    IssuedTokenParametersSecurityKey = KeyingMaterial.RsaSecurityKey_1024,
                    IssuedSecurityTokenParametersKeyType = System.IdentityModel.Tokens.SecurityKeyType.AsymmetricKey,
                    RequestContext = null
                },
                new WsFederationHttpBindingTheoryData
                {
                    IssuedTokenParametersSecurityKey = KeyingMaterial.DefaultSymmetricSecurityKey_56,
                    IssuedSecurityTokenParametersKeyType = System.IdentityModel.Tokens.SecurityKeyType.SymmetricKey,
                    RequestContext = null
                },
                new WsFederationHttpBindingTheoryData
                {
                    IssuedTokenParametersSecurityKey = null,
                    IssuedSecurityTokenParametersKeyType = System.IdentityModel.Tokens.SecurityKeyType.BearerKey,
                    RequestContext = null
                },

                new WsFederationHttpBindingTheoryData
                {
                    IssuedTokenParametersSecurityKey = KeyingMaterial.RsaSecurityKey_1024,
                    IssuedSecurityTokenParametersKeyType = System.IdentityModel.Tokens.SecurityKeyType.AsymmetricKey,
                    RequestContext = string.Empty
                },
            };
        }

        public static SecurityTokenProvider GetProviderForBinding(Binding binding)
        {
            var factory = new ChannelFactory<IRequestChannel>(binding, new EndpointAddress(new Uri("https://localhost")));

            // TODO: This substitution shouldn't be necessary in the future.
            factory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            factory.Endpoint.EndpointBehaviors.Add(new WsTrustChannelClientCredentials());

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
