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

using System;
using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Defines supported elements of WsTrust Request and Response messages.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    abstract public class WsTrustMessage : IXmlOpenItem
    {
        private SecurityTokenElement _actAs;
        private AdditionalContext _additionalContext;
        private AppliesTo _appliesTo;
        private string _authenticationType;
        private BinaryExchange _binaryExchange;
        private string _canonicalizationAlgorithm;
        private string _context;
        private SecurityTokenReference _delegateTo;
        private SecurityTokenElement _encryption;
        private string _encryptionAlgorithm;
        private string _encryptWith;
        private Entropy _entropy;
        private EndpointReference _issuer;
        private int? _keySizeInBits;
        private string _keyType;
        private string _keyWrapAlgorithm;
        private Lifetime _lifetime;
        private SecurityTokenElement _onBehalfOf;
        private Participants _participants;
        private PolicyReference _policyReference;
        private SecurityTokenElement _proofEncryption;
        private Claims _requestClaims;
        private WsTrustRequest _secondaryParameters;
        private string _signatureAlgorithm;
        private string _signWith;
        private string _tokenType;
        private WsTrustVersion _wsTrustVersion;
        private UseKey _useKey;

        /// <summary>
        /// Gets or sets a SecurityTokenElement representing the ActAs element used to convey information about the identity to be represented in the token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ActAs is null.</exception>
        public SecurityTokenElement ActAs
        {
            get => _actAs;
            set => _actAs = value ?? throw LogHelper.LogArgumentNullException(nameof(ActAs));
        }

        /// <summary>
        /// Gets or sets a value representing the AdditionalContext used to convey desired properties of the token.
        /// <para>see: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if AdditionalContext is null.</exception>
        public AdditionalContext AdditionalContext
        {
            get => _additionalContext;
            set => _additionalContext = value ?? throw LogHelper.LogArgumentNullException(nameof(AdditionalContext));
        }

        /// <summary>
        /// Gets or sets a value representing the AppliesTo element that specifies the scope for which the security token is desired.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html#_Toc162064962 </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if AppliesTo is null.</exception>
        public AppliesTo AppliesTo
        {
            get => _appliesTo;
            set => _appliesTo = value ?? throw LogHelper.LogArgumentNullException(nameof(AppliesTo));
        }

        /// <summary>
        /// Gets or sets a string representing the AuthenticationType element that indicates the type of authencation desired, usually specified as a URI.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if AuthenticationType is null or empty.</exception>
        public string AuthenticationType
        {
            get => _authenticationType;
            set => _authenticationType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a value representing the BinaryExchange element that is used to exchange binary blobs as part of the existing negotiation.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if BinaryExchange is null.</exception>
        public BinaryExchange BinaryExchange
        {
            get => _binaryExchange;
            set => _binaryExchange = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets a string representing the CanonicalizationAlgorithm desired method to use in the returned token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if CanonicalizationAlgorithm is null or empty.</exception>
        public string CanonicalizationAlgorithm
        {
            get => _canonicalizationAlgorithm;
            set => _canonicalizationAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a value representing the Claims element used to request a specific set of claims.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Claims is null.</exception>
        public Claims Claims
        {
            get => _requestClaims;
            set => _requestClaims = value ?? throw LogHelper.LogArgumentNullException(nameof(Claims));
        }

        /// <summary>
        /// Gets or sets a string that represents the desired algorithm to use when computed keys are used.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ComputedKeyAlgorithm is null or empty.</exception>
        public string ComputedKeyAlgorithm
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a string that reprents the Context attribute that established for a set of RSTR messages.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Context is null or empty.</exception>
        public string Context
        {
            get => _context;
            set => _context = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a boolean that specifies if the returned token should be delegatable.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        public bool? Delegatable
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Identity to which the Issued Token is delegated to.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if DelegateTo is null or empty.</exception>
        public SecurityTokenReference DelegateTo
        {
            get => _delegateTo;
            set => _delegateTo = value ?? throw LogHelper.LogArgumentNullException(nameof(DelegateTo));
        }

        /// <summary>
        /// Gets or sets a value repsenting the Entropy element that is used to provide proposed key material.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        public Entropy Entropy
        {
            get => _entropy;
            set => _entropy = value ?? throw LogHelper.LogArgumentNullException(nameof(Entropy));
        }

        /// <summary>
        /// Gets or sets a value that represents the Encryption element that indicates the requestor desires any secrects to be encrypted with a specific token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Encryption is null.</exception>
        public SecurityTokenElement Encryption
        {
            get => _encryption;
            set => _encryption = value ?? throw LogHelper.LogArgumentNullException(nameof(Encryption));
        }

        /// <summary>
        /// Gets or sets a string that indicates the desired EncryptionAlgorithm to use.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if EncryptionAlgorithm is null or empty.</exception>
        public string EncryptionAlgorithm
        {
            get => _encryptionAlgorithm;
            set => _encryptionAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a string that indicates the desired encryption algorithm to use with the issued security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if EncryptWith is null or an empty.</exception>
        public string EncryptWith
        {
            get => _encryptWith;
            set => _encryptWith = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(EncryptWith)) : value;
        }

        /// <summary>
        /// Gets or sets a boolean that specifies if the Issued Token should be marked forwardable.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        public bool? Forwardable
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets this element that defines the KeySize element inside the RequestSecurityToken message
        /// It is specified in bits.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if KeySizeInBits is &lt; 0.</exception>
        public int? KeySizeInBits
        {
            get => _keySizeInBits;
            set => _keySizeInBits = (value.HasValue && value.Value < 0) ? throw LogHelper.LogExceptionMessage(new ArgumentException("must be greater than 0", nameof(KeySizeInBits))) : value;
        }

        /// <summary>
        /// Gets or sets a string that indicates the desired type of key in the security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if KeyType is null or empty.</exception>
        public string KeyType
        {
            get => _keyType;
            set => _keyType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(KeyType)) : value;
        }

        /// <summary>
        /// Gets or sets a string that indicates the desired key wrapping algorithm.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if KeyWrapAlgorithm is null or empty.</exception>
        public string KeyWrapAlgorithm
        {
            get => _keyWrapAlgorithm;
            set => _keyWrapAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(KeyWrapAlgorithm)) : value;
        }

        /// <summary>
        /// Gets or sets the a value that represents the Lifetime element used to specify the desired valid time range.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Lifetime is null or empty.</exception>
        public Lifetime Lifetime
        {
            get => _lifetime;
            set => _lifetime = value ?? throw LogHelper.LogArgumentNullException(nameof(Lifetime));
        }

        /// <summary>
        /// Gets or sets an EndpointReference that represents the Issuer element used to specify the issuer of the security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Issuer is null.</exception>
        public EndpointReference Issuer
        {
            get => _issuer;
            set => _issuer = value ?? throw LogHelper.LogArgumentNullException(nameof(Issuer));
        }

        /// <summary>
        /// Gets or sets an EndpointReference that represents the Issuer element used to specify the issuer of the security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if OnBehalfOf is null.</exception>
        public SecurityTokenElement OnBehalfOf
        {
            get => _onBehalfOf;
            set => _onBehalfOf = value ?? throw LogHelper.LogArgumentNullException(nameof(OnBehalfOf));
        }

        /// <summary>
        /// Gets or sets an value that represents the Participants element used to specify the parcipants sharing the security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if Participants is null.</exception>
        public Participants Participants
        {
            get => _participants;
            set => _participants = value ?? throw LogHelper.LogArgumentNullException(nameof(Participants));
        }

        /// <summary>
        /// Gets or sets an value that represents the PolicyReference element used to specify the parcipants sharing the security token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if PolicyReference is null.</exception>
        public PolicyReference PolicyReference
        {
            get => _policyReference;
            set => _policyReference = value ?? throw LogHelper.LogArgumentNullException(nameof(PolicyReference));
        }

        /// <summary>
        /// Gets or sets a SecurityTokenElement that represents the ProofEncryption element used to specify the any secrets in  proof-of-possession tokens to be encrypted for the specified token.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ProofEncryption is null.</exception>
        public SecurityTokenElement ProofEncryption
        {
            get => _proofEncryption;
            set => _proofEncryption = value ?? throw LogHelper.LogArgumentNullException(nameof(ProofEncryption));
        }

        /// <summary>
        /// Gets of sets a WsTrustRequest that represents the Secondary element for which the requestor is not the originator.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if SecondaryParameters is null.</exception>
        public WsTrustRequest SecondaryParameters
        {
            get => _secondaryParameters;
            set => _secondaryParameters = value ?? throw LogHelper.LogArgumentNullException(nameof(SecondaryParameters));
        }

        /// <summary>
        /// Gets or sets a string that represents the SignatureAlgorithm that indicates the desired signature algorithm to signe the issued security token with.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ComputedKeyAlgorithm is null or empty.</exception>
        public string SignatureAlgorithm
        {
            get => _signatureAlgorithm;
            set => _signatureAlgorithm = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a string that represents the SignWith element that indicates the desired signature algorithm to be used with the issued security token by the receiver.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ComputedKeyAlgorithm is null or empty.</exception>
        public string SignWith
        {
            get => _signWith;
            set => _signWith = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets a string that represents the TokenType element.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">if TokenType is null or empty.</exception>
        public string TokenType
        {
            get => _tokenType;
            set => _tokenType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }

        // TODO - can this be determined from the version of the request passed in the ctor of WsTrustRequest or when creating a WsTrustResponse.
        /// <summary>
        /// Gets or sets the WsTrustVesion.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if ComputedKeyAlgorithm is null or empty.</exception>
        public WsTrustVersion WsTrustVersion
        {
            get => _wsTrustVersion;
            set => _wsTrustVersion = value ?? throw LogHelper.LogArgumentNullException(nameof(WsTrustVersion));
        }

        /// <summary>
        /// Gets or sets an value that represents the UseKey element used to specify that the requestor wishes to use an existing key rather than create a new one.
        /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if UseKey is null or empty.</exception>
        public UseKey UseKey
        {
            get => _useKey;
            set => _useKey = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets additional attributes that should be added to or were found when reading or writing a trust message.
        /// </summary>
        public IList<XmlAttribute> AdditionalXmlAttributes { get; } = new List<XmlAttribute>();

        /// <summary>
        /// Gets additional elements that should be added to or were found when reading or writing a trust message.
        /// </summary>
        public IList<XmlElement> AdditionalXmlElements { get; } = new List<XmlElement>();
    }
}
