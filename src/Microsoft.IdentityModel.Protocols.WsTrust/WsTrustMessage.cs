//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Contains all the possible elements of WsTrust RST / RSTR message
    /// </summary>
    public class WsTrustMessage : IXmlOpenItem
    {
        private AppliesTo _appliesTo;
        private string _authenticationType;
        private BinaryExchange _binaryExchange;
        private string _canonicalizationAlgorithm;
        private string _context;
        private string _encryptionAlgorithm;
        private string _encryptWith;
        private Entropy _entropy;
        private int? _keySizeInBits;
        private string _keyWrapAlgorithm;
        private Lifetime _lifetime;
        private Claims _requestClaims;
        private string _signatureAlgorithm;
        private string _signWith;
        private string _tokenType;
        private UseKey _useKey;

        /// <summary>
        /// 
        /// </summary>
        public WsTrustMessage()
        {
        }

        /// <summary>
        /// 
        /// </summary>
        public AdditionalContext AdditionalContext { get; set; }

        /// <summary>
        /// Gets or sets the optional element contains the actor.
        /// on to act as another.
        /// </summary>
        public string ActAs { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public bool AllowPostdating { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public AppliesTo AppliesTo
        {
            get => _appliesTo;
            set => _appliesTo = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the optional element indicates the type of authencation desired,
        /// specified as a URI.
        /// </summary>
        public string AuthenticationType
        {
            get => _authenticationType;
            set => _authenticationType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the binary data that is exchanged.
        /// </summary>
        public BinaryExchange BinaryExchange
        {
            get => _binaryExchange;
            set => _binaryExchange = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityTokenElement"/> that is to be cancelled.
        /// </summary>
        public SecurityTokenElement CancelTarget { get; set; }

        /// <summary>
        /// Gets or sets the CanonicalizationAlgorithm.
        /// </summary>
        public string CanonicalizationAlgorithm
        {
            get => _canonicalizationAlgorithm;
            set => _canonicalizationAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// The optional element requests a specific set of claim types requested by the client.
        /// </summary>
        public Claims Claims
        {
            get => _requestClaims;
            set => _requestClaims = value ?? throw LogHelper.LogArgumentNullException(nameof(Claims));
        }

        /// <summary>
        /// 
        /// </summary>
        public string ComputedKeyAlgorithm { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string Context
        {
            get => _context;
            set => _context = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or Sets a boolean that specifies if the returned token should
        /// be delegatable.
        /// </summary>
        public bool? Delegatable { get; set; }

        /// <summary>
        /// Gets or Sets the Identity to which the Issued Token is delegated to.
        /// </summary>
        public SecurityTokenElement DelegateTo { get; set; }

        /// <summary>
        /// Gets or Sets a boolean that specifies if the Issued Token should
        /// be marked forwardable.
        /// </summary>
        public bool? Forwardable { get; set; }

        /// <summary>
        /// Gets or sets entropy to send
        /// </summary>
        public Entropy Entropy
        {
            get => _entropy;
            set => _entropy = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// The optional element provides that provides information on the token/key to use when encrypting
        /// </summary>
        public SecurityTokenElement Encryption { get; set; }

        /// <summary>
        /// Gets or sets the EncryptionAlgorithm that is used to encrypt the token returned.
        /// </summary>
        public string EncryptionAlgorithm
        {
            get => _encryptionAlgorithm;
            set => _encryptionAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the encryption algorithm to use.
        /// </summary>
        /// <exception cref="ArgumentNullException"> if value is null or an empty.</exception>
        public string EncryptWith
        {
            get => _encryptWith;
            set => _encryptWith = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets this element that defines the KeySize element inside the RequestSecurityToken message
        /// It is specified in bits.
        /// </summary>
        public int? KeySizeInBits
        {
            get => _keySizeInBits;
            set => _keySizeInBits = (value.HasValue && value.Value < 0) ? throw LogHelper.LogExceptionMessage(new ArgumentException("must be greater than 0", nameof(value))) : value;
        }

        /// <summary>
        /// Gets or sets the KeyType.
        /// </summary>
        public string KeyType { get; set; }

        /// <summary>
        /// Gets or sets wst:KeyWrapAlgorithm.
        /// </summary>
        public string KeyWrapAlgorithm
        {
            get => _keyWrapAlgorithm;
            set => _keyWrapAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the Lifetime.
        /// </summary>
        public Lifetime Lifetime
        {
            get => _lifetime;
            set => _lifetime = value ?? throw LogHelper.LogArgumentNullException(nameof(Lifetime));
        }

        /// <summary>
        /// Gets/Sets the Issuer of the OnBehalfOf token.
        /// </summary>
        public EndpointReference Issuer { get; set; }

        /// <summary>
        ///
        /// </summary>
        public SecurityToken OnBehalfOf { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Participants Participants { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public PolicyReference PolicyReference { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey" /> that will send to the STS to encrypt the proof token.
        /// </summary>
        public SecurityKey ProofEncryptionKey { get; set; }

        /// <summary>
        /// Gets or sets the Renewing element inside the RequestSecurityToken message.
        /// </summary>
        public Renewing Renewing { get; set; }

        /// <summary>
        /// Gets or sets the RenewTarget element inside the RequestSecurityToken message.
        /// </summary>
        public SecurityTokenElement RenewTarget { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string RequestType { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public WsTrustRequest SecondaryParameters { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string SignatureAlgorithm
        {
            get => _signatureAlgorithm;
            set => _signatureAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// 
        /// </summary>
        public string SignWith
        {
            get => _signWith;
            set => _signWith = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the TokenType.
        /// </summary>
        public string TokenType
        {
            get => _tokenType;
            set => _tokenType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// 
        /// </summary>
        public WsTrustVersion WsTrustVersion { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public UseKey UseKey
        {
            get => _useKey;
            set => _useKey = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or Sets the Security Token to be Validated.
        /// </summary>
        public SecurityTokenElement ValidateTarget { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IList<XmlAttribute> AdditionalXmlAttributes { get; } = new List<XmlAttribute>();

        /// <summary>
        /// 
        /// </summary>
        public IList<XmlElement> AdditionalXmlElements { get; } = new List<XmlElement>();
    }
}
