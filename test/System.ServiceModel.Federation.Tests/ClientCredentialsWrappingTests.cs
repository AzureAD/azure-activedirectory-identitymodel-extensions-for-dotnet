using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Threading;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace System.ServiceModel.Federation.Tests
{
    public class ClientCredentialsWrappingTests
    {
        [Fact]
        public void WrapsClientCredentials()
        {
            var issuedTokenParameters = new IssuedTokenParameters
            {
                IssuerAddress = new EndpointAddress(new Uri("https://localhost")),
                IssuerBinding = new WSHttpBinding(SecurityMode.Transport),
                SecurityKey = KeyingMaterial.RsaSecurityKey_1024,
                Target = "https://localhost",
                TokenType = Saml2Constants.OasisWssSaml2TokenProfile11
            };

            var binding = new CustomBinding(new WsFederationHttpBinding(issuedTokenParameters)
            {
                WSTrustContext = "DummyContext"
            });
            var clientCredentialCapturingBindingElement = new ClientCredentialCapturingBindingElement();
            binding.Elements.Insert(1, clientCredentialCapturingBindingElement);

            var clientCredentials = new ClientCredentials();
            clientCredentials.UserName.UserName = "Foo";
            clientCredentials.UserName.Password = "Bar";
            var cf = binding.BuildChannelFactory<IRequestChannel>(clientCredentials);
            Assert.NotNull(clientCredentialCapturingBindingElement.CapturedCredentials);
            Assert.IsType<WsTrustChannelClientCredentials>(clientCredentialCapturingBindingElement.CapturedCredentials);
            var stm = clientCredentialCapturingBindingElement.CapturedCredentials.CreateSecurityTokenManager();
            var tokenRequirementType = typeof(ClientCredentials).Assembly.GetType("System.ServiceModel.Security.Tokens.InitiatorServiceModelSecurityTokenRequirement");
            var initiatorTokenRequirement = (SecurityTokenRequirement)Activator.CreateInstance(tokenRequirementType);
            initiatorTokenRequirement.TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/UserName";
            var provider = stm.CreateSecurityTokenProvider(initiatorTokenRequirement);
            var token = provider.GetToken(Timeout.InfiniteTimeSpan);
            Assert.Equal("UserNameSecurityToken", token.GetType().Name);
            Assert.Equal("Foo", (string)token.GetType().GetProperty("UserName").GetValue(token));
            Assert.Equal("Bar", (string)token.GetType().GetProperty("Password").GetValue(token));
        }

        [Fact]
        public void ProvidesOtherTokenProviders()
        {
            var credentials = new WsTrustChannelClientCredentials();
            credentials.UserName.UserName = "Foo";
            credentials.UserName.Password = "Bar";
            var stm = credentials.CreateSecurityTokenManager();
            var tokenRequirementType = typeof(ClientCredentials).Assembly.GetType("System.ServiceModel.Security.Tokens.InitiatorServiceModelSecurityTokenRequirement");
            var initiatorTokenRequirement = (SecurityTokenRequirement)Activator.CreateInstance(tokenRequirementType);
            initiatorTokenRequirement.TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/UserName";
            var provider = stm.CreateSecurityTokenProvider(initiatorTokenRequirement);
            var token = provider.GetToken(Timeout.InfiniteTimeSpan);
            Assert.Equal("UserNameSecurityToken", token.GetType().Name);
            Assert.Equal("Foo", (string)token.GetType().GetProperty("UserName").GetValue(token));
            Assert.Equal("Bar", (string)token.GetType().GetProperty("Password").GetValue(token));
        }
    }

    internal class ClientCredentialCapturingBindingElement : BindingElement
    {
        
        public ClientCredentialCapturingBindingElement()
        {
        }

        public ClientCredentials CapturedCredentials { get; set; }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            foreach(var item in context.BindingParameters)
            {
                if(item is ClientCredentials clientCredentials)
                {
                    CapturedCredentials = clientCredentials;
                    break;
                }
            }

            return context.BuildInnerChannelFactory<TChannel>();
        }

        public override bool CanBuildChannelFactory<TChannel>(BindingContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.BindingParameters.Add(this);
            return context.CanBuildInnerChannelFactory<TChannel>();
        }

        public override BindingElement Clone()
        {
            return this;
        }

        public override T GetProperty<T>(BindingContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.GetInnerProperty<T>();
        }
    }
}
