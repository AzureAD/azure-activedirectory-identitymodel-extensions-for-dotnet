using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    class MockRequestChannel : IRequestChannel
    {
        public Message Request(Message message)
        {
            // Get test SAML2 token
            var tokenHandler = new Saml2SecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
            SecurityToken samlToken = tokenHandler.CreateToken(tokenDescriptor);
            string signedToken = tokenHandler.WriteToken(samlToken);
            SecurityToken signedSamlToken = tokenHandler.ReadToken(signedToken);

            // Create mock WsTrustResponse containing the SAML2 token
            var response = new WsTrustResponse(new RequestSecurityTokenResponse
            {
                RequestedSecurityToken = new RequestedSecurityToken(signedSamlToken),
                RequestedProofToken = new RequestedProofToken(new BinarySecret(Guid.NewGuid().ToByteArray())),
                AttachedReference = new SecurityTokenReference
                {
                    KeyIdentifier = new KeyIdentifier
                    {
                        EncodingType = WsSecurityEncodingTypes.WsSecurity11.Base64,
                        Id = "KeyIdentifier",
                        ValueType = "ValueType"
                    },
                    TokenType = "TokenType"
                }
            });

            // Return a message object with the WsTrustResponse as its body
            return Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.Trust13.IssueFinal, new WsTrustResponseBodyWriter(response));
        }


        public EndpointAddress RemoteAddress => throw new NotImplementedException();

        public Uri Via => throw new NotImplementedException();

        public CommunicationState State => throw new NotImplementedException();

        public event EventHandler Closed;
        public event EventHandler Closing;
        public event EventHandler Faulted;
        public event EventHandler Opened;
        public event EventHandler Opening;

        public void Abort()
        {
            Faulted?.Invoke(null, null);
            throw new NotImplementedException();
        }

        public IAsyncResult BeginClose(AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public IAsyncResult BeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public IAsyncResult BeginOpen(AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public IAsyncResult BeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            throw new NotImplementedException();
        }

        public void Close()
        {
            Closing?.Invoke(null, null);
            Closed?.Invoke(null, null);
            throw new NotImplementedException();
        }

        public void Close(TimeSpan timeout)
        {
            throw new NotImplementedException();
        }

        public void EndClose(IAsyncResult result)
        {
            throw new NotImplementedException();
        }

        public void EndOpen(IAsyncResult result)
        {
            throw new NotImplementedException();
        }

        public Message EndRequest(IAsyncResult result)
        {
            throw new NotImplementedException();
        }

        public T GetProperty<T>() where T : class
        {
            throw new NotImplementedException();
        }

        public void Open()
        {
            throw new NotImplementedException();
        }

        public void Open(TimeSpan timeout)
        {
            Opening?.Invoke(null, null);
            Opened?.Invoke(null, null);
            throw new NotImplementedException();
        }

        public Message Request(Message message, TimeSpan timeout)
        {
            throw new NotImplementedException();
        }
    }
}
