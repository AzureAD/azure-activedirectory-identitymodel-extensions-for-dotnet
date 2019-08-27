// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

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
        public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(10);
        public string LastActionSent { get; private set; }

        public MockResponseSettings ResponseSettings { get; }

        public MockRequestChannel(MockResponseSettings responseSettings)
        {
            ResponseSettings = responseSettings;
        }

        public Message Request(Message message)
        {
            LastActionSent = message.Headers.Action;

            // Create mock WsTrustResponse containing the SAML2 token and the specified lifetime
            DateTime issuedAt = DateTime.UtcNow;
            var response = new WsTrustResponse(new RequestSecurityTokenResponse
            {
                RequestedSecurityToken = new RequestedSecurityToken(GetSaml2Token(issuedAt)),
                AttachedReference = new SecurityTokenReference
                {
                    KeyIdentifier = new KeyIdentifier
                    {
                        EncodingType = WsSecurityEncodingTypes.WsSecurity11.Base64,
                        Id = "KeyIdentifier",
                        ValueType = "ValueType"
                    },
                    TokenType = "TokenType"
                },
                UnattachedReference = new SecurityTokenReference
                {
                    KeyIdentifier = new KeyIdentifier
                    {
                        EncodingType = WsSecurityEncodingTypes.WsSecurity11.Base64,
                        Id = "KeyIdentifier2",
                        ValueType = "ValueType2"
                    },
                    TokenType = "TokenType2"
                },
                Lifetime = new Lifetime(issuedAt, issuedAt.Add(TokenLifetime))
            });

            if (ResponseSettings != null)
            {
                if (ResponseSettings.Entropy != null)
                {
                    response.RequestSecurityTokenResponseCollection[0].Entropy = ResponseSettings.Entropy;
                }
                if (ResponseSettings.KeySizeInBits != null)
                {
                    response.RequestSecurityTokenResponseCollection[0].KeySizeInBits = ResponseSettings.KeySizeInBits;
                }
                if (ResponseSettings.KeyType != null)
                {
                    response.RequestSecurityTokenResponseCollection[0].KeyType = ResponseSettings.KeyType;
                }
                if (ResponseSettings.Lifetime != null)
                {
                    response.RequestSecurityTokenResponseCollection[0].Lifetime = ResponseSettings.Lifetime;
                }
                if (ResponseSettings.ProofToken != null)
                {
                    response.RequestSecurityTokenResponseCollection[0].RequestedProofToken = ResponseSettings.ProofToken;
                }
            }

            // Return a message object with the WsTrustResponse as its body
            return Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.Trust13.IssueFinal, new WsTrustResponseBodyWriter(response));
        }

        /// <summary>
        /// Create a test SAML2 token. This creates new tokens instead of using reference tokens from TestUtil
        /// so that the tokens will all have separate IDs which makes it easier to distinguish new tokens from
        /// cached tokens.
        /// </summary>
        /// <param name="issuedAt">The time to use for the token's IssuedAt property</param>
        /// <returns>A test token with a unique ID and the specified IssuedAt</returns>
        private SecurityToken GetSaml2Token(DateTime issuedAt)
        {
            var tokenHandler = new Saml2SecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
            tokenDescriptor.IssuedAt = issuedAt;
            tokenDescriptor.Expires = issuedAt.Add(TokenLifetime);
            return tokenHandler.CreateToken(tokenDescriptor);
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
