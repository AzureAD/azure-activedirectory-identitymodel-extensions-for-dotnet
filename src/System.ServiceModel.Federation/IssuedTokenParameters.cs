// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace System.ServiceModel.Federation
{
    public class IssuedTokenParameters
    {
        private EndpointAddress _issuerAddress;
        private Binding _issuerBinding;
        private string _keyType;
        private string _target;
        private string _tokenType;

        /// <summary>
        /// Values that are used to obtain a token from an IdentityProvider
        /// </summary>
        public IssuedTokenParameters()
        {
            AdditionalRequestParameters = new List<XmlElement>();
            ClaimTypes = new List<ClaimType>();
        }

        public IssuedSecurityTokenParameters CreateIssuedSecurityTokenParameters()
        {
            return new IssuedSecurityTokenParameters
            {
                IssuerAddress = IssuerAddress,
                IssuerBinding = IssuerBinding,
                // TODO - brentsch - there needs to be a mapping from string - enum if no changes can be made in ServiceModel.
                // TODO - brentsch - BearerKey is currently not supported, with standard WCF libraries, this will fault.
                KeyType = IdentityModel.Tokens.SecurityKeyType.BearerKey,
                TokenType = TokenType
            };
        }

        public IList<XmlElement> AdditionalRequestParameters
        {
            get;
        }

        public IList<ClaimType> ClaimTypes
        {
            get;
        }

        public EndpointAddress IssuerAddress
        {
            get => _issuerAddress;
            set => _issuerAddress = value ?? throw new ArgumentNullException(nameof(IssuerAddress));
        }

        public Binding IssuerBinding
        {
            get => _issuerBinding;
            set => _issuerBinding = value ?? throw new ArgumentNullException(nameof(IssuerBinding));

        }

        public string KeyType
        {
            // TODO - brentsch - only bearer keys currently supported
            get => _keyType;
            set => _keyType = (string.IsNullOrEmpty(value))
                            ? throw new ArgumentNullException(nameof(KeyType))
                            : value;
        }

        public SecurityKey SecurityKey { get; set; }

        public string TokenType
        {
            // TODO - brentsch - only SAML2 tokens supported
            get => _tokenType;
            set => _tokenType = (string.IsNullOrEmpty(value))
                            ? throw new ArgumentNullException(nameof(TokenType))
                            : (value.Equals(Saml2Constants.OasisWssSaml2TokenProfile11))
                                ? value
                                : throw new NotSupportedException($"Only '{Saml2Constants.OasisWssSaml2TokenProfile11}' are supported, keyType was '{value}'.");

        }

        public int? KeySize
        {
            get;
            set;
        }

        public string Target
        {
            get => _target;
            set => _target = !string.IsNullOrEmpty(value) ? value : throw new ArgumentNullException(nameof(Target));
        }

        public WsTrustVersion WsTrustVersion
        {
            get;
            set;
        }
    }
}
