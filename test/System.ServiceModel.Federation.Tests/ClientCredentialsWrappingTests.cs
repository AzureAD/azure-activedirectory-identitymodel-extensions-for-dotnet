/*
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
        [Theory, MemberData(nameof(CredentialsTheoryData))]
        public void WrapsClientCredentials(ClientCredentialsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WrapsClientCredentials", theoryData);

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
            var cf = binding.BuildChannelFactory<IRequestChannel>(theoryData.ClientCredentials);
            Assert.NotNull(clientCredentialCapturingBindingElement.CapturedCredentials);
            Assert.IsType<WsTrustChannelClientCredentials>(clientCredentialCapturingBindingElement.CapturedCredentials);
            var stm = clientCredentialCapturingBindingElement.CapturedCredentials.CreateSecurityTokenManager();
            var provider = stm.CreateSecurityTokenProvider(theoryData.TokenRequirement);
            var token = provider.GetToken(Timeout.InfiniteTimeSpan);
            IdentityComparer.AreEqual(token.GetType(), theoryData.TokenType, context);
            IdentityComparer.AreEqual(token, theoryData.ClientCredentials, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(WSTrustCredentialsTheoryData))]
        public void ProvidesOtherTokenProviders(ClientCredentialsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ProvidesOtherTokenProviders", theoryData);

            var stm = theoryData.ClientCredentials.CreateSecurityTokenManager();
            var provider = stm.CreateSecurityTokenProvider(theoryData.TokenRequirement);
            var token = provider.GetToken(Timeout.InfiniteTimeSpan);
            IdentityComparer.AreEqual(token.GetType(), theoryData.TokenType, context);
            IdentityComparer.AreEqual(token, theoryData.ClientCredentials, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ClientCredentialsTheoryData> WSTrustCredentialsTheoryData
        {
            get => CreateTheoryData<WsTrustChannelClientCredentials>();
        }

        public static TheoryData<ClientCredentialsTheoryData> CredentialsTheoryData
        {
            get => CreateTheoryData<ClientCredentials>();
        }

        private static TheoryData<ClientCredentialsTheoryData> CreateTheoryData<T>() where T : ClientCredentials, new()
        {
            var theoryData = new TheoryData<ClientCredentialsTheoryData>();
            ClientCredentials credentials = new T();
            credentials.UserName.UserName = "Foo";
            credentials.UserName.Password = "Bar";
            var tokenRequirementType = typeof(ClientCredentials).Assembly.GetType("System.ServiceModel.Security.Tokens.InitiatorServiceModelSecurityTokenRequirement");
            var initiatorTokenRequirement = (SecurityTokenRequirement)Activator.CreateInstance(tokenRequirementType);
            initiatorTokenRequirement.TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/UserName";
            theoryData.Add(new ClientCredentialsTheoryData
            {
                TestId = "UserNameAuthentication",
                ClientCredentials = credentials,
                TokenType = typeof(ClientCredentials).Assembly.GetType("System.IdentityModel.Tokens.UserNameSecurityToken"),
                TokenRequirement = initiatorTokenRequirement
            });
            credentials = new T();
            credentials.Windows.ClientCredential.UserName = "Foz";
            credentials.Windows.ClientCredential.Password = "Baz";
            credentials.Windows.ClientCredential.Domain = "Bab";
            initiatorTokenRequirement = (SecurityTokenRequirement)Activator.CreateInstance(tokenRequirementType);
            initiatorTokenRequirement.TokenType = "http://schemas.microsoft.com/ws/2006/05/servicemodel/tokens/SspiCredential";
            theoryData.Add(new ClientCredentialsTheoryData
            {
                TestId = "WindowsAuthentication",
                ClientCredentials = credentials,
                TokenType = typeof(ClientCredentials).Assembly.GetType("System.ServiceModel.Security.Tokens.SspiSecurityToken"),
                TokenRequirement = initiatorTokenRequirement
            });
            return theoryData;
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

            foreach (var item in context.BindingParameters)
            {
                if (item is ClientCredentials clientCredentials)
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
*/