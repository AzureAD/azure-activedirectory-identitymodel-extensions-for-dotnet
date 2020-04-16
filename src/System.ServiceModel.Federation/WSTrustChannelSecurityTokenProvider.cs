// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.ComponentModel;

namespace System.ServiceModel.Federation
{

    /// <summary>
    /// Custom WSTrustChannelSecurityTokenProvider that returns a SAML assertion
    /// </summary>
    public class WSTrustChannelSecurityTokenProvider : SecurityTokenProvider
    {
        private const int DefaultPublicKeySize = 1024;
        private const string Namespace = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement";
        private const string IssuedSecurityTokenParametersProperty = Namespace + "/IssuedSecurityTokenParameters";
        private const string SecurityAlgorithmSuiteProperty = Namespace + "/SecurityAlgorithmSuite";
        private const string SecurityBindingElementProperty = Namespace + "/SecurityBindingElement";
        private const string TargetAddressProperty = Namespace + "/TargetAddress";

        internal const bool DefaultCacheIssuedTokens = true;
        internal static readonly TimeSpan DefaultMaxIssuedTokenCachingTime = TimeSpan.MaxValue;
        internal const int DefaultIssuedTokenRenewalThresholdPercentage = 60;

        private readonly IssuedSecurityTokenParameters _issuedTokenParameters;
        private TimeSpan _maxIssuedTokenCachingTime = DefaultMaxIssuedTokenCachingTime;
        private int _issuedTokenRenewalThresholdPercentage = DefaultIssuedTokenRenewalThresholdPercentage;
        private SecurityKeyEntropyMode _keyEntropyMode;
        private MessageSecurityVersion _messageSecurityVersion;
        private readonly ChannelFactory<IRequestChannel> _channelFactory;
        private readonly SecurityAlgorithmSuite _securityAlgorithmSuite;

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement) : this(tokenRequirement, null)
        { }

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, string requestContext)
        {
            SecurityTokenRequirement = tokenRequirement ?? throw new ArgumentNullException(nameof(tokenRequirement));
            SecurityTokenRequirement.TryGetProperty(SecurityAlgorithmSuiteProperty, out _securityAlgorithmSuite);
            _issuedTokenParameters = SecurityTokenRequirement.GetProperty<IssuedSecurityTokenParameters>(IssuedSecurityTokenParametersProperty);
            InitializeKeyEntropyMode();
            InitializeMessageSecurityVersion();
            RequestContext = string.IsNullOrEmpty(requestContext) ? Guid.NewGuid().ToString() : requestContext;
            _channelFactory = CreateChannelFactory();
        }

        private void InitializeKeyEntropyMode()
        {
            // Default to combined entropy unless another option is specified in the issuer's security binding element.
            // In previous versions of .NET WsTrust token providers, it was possible to set the default key entropy mode in client credentials.
            // That scenario does not seem to be needed in .NET Core WsTrust scenarios, so key entropy mode is simply being read from the issuer's
            // security binding element. If, in the future, it's necessary to change the default (if some scenarios don't have a security binding
            // element, for example), that could be done by adding a DefaultKeyEntropyMode property to WsTrustChannelCredentials and moving
            // the code that calculates KeyEntropyMode out to WsTrustChannelSecurityTokenManager since it can set this property
            // when it creates the provider and fall back to the credentials' default value if no security binding element is present.
            KeyEntropyMode = SecurityKeyEntropyMode.CombinedEntropy;
            SecurityBindingElement securityBindingElement = IssuerBinding?.CreateBindingElements().Find<SecurityBindingElement>();
            if (securityBindingElement != null)
            {
                KeyEntropyMode = securityBindingElement.KeyEntropyMode;
            }
        }

        /// <summary>
        /// Set initial MessageSecurityVersion based on (in priority order):
        ///  1. The message security version of the issuer binding's security binding element.
        ///  2. The provided DefaultMessageSecurityVersion from issued token parameters.
        ///  3. The message security version of the outer security binding element (from the security token requirement).
        ///  4. MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11
        /// </summary>
        private void InitializeMessageSecurityVersion()
        {
            SecurityBindingElement issuerSecurityBindingElement = IssuerBinding?.CreateBindingElements().Find<SecurityBindingElement>();
            MessageSecurityVersion messageSecurityVersion = issuerSecurityBindingElement?.MessageSecurityVersion;

            if (messageSecurityVersion == null)
            {
                messageSecurityVersion = _issuedTokenParameters.DefaultMessageSecurityVersion;
            }

            if (messageSecurityVersion == null)
            {
                if (SecurityTokenRequirement.TryGetProperty(SecurityBindingElementProperty, out SecurityBindingElement outerSecurityBindingElement))
                {
                    messageSecurityVersion = outerSecurityBindingElement.MessageSecurityVersion;
                }
            }

            if (messageSecurityVersion == null)
            {
                messageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11;
            }

            MessageSecurityVersion = messageSecurityVersion;
        }

        protected virtual ChannelFactory<IRequestChannel> CreateChannelFactory()
        {
            var factory = new ChannelFactory<IRequestChannel>(IssuerBinding, _issuedTokenParameters.IssuerAddress);

            // Temporary as test STS is not trusted.
            // This code should be removed.
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication();
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

            return factory;
        }

        protected virtual WsTrustRequest CreateWsTrustRequest()
        {
            EndpointAddress target = SecurityTokenRequirement.GetProperty<EndpointAddress>(TargetAddressProperty);

            int keySize;
            string keyType;

            switch (_issuedTokenParameters.KeyType)
            {
                case SecurityKeyType.AsymmetricKey:
                    keySize = DefaultPublicKeySize;
                    keyType = WsTrustKeyTypes.PublicKey;
                    break;
                case SecurityKeyType.SymmetricKey:
                    keySize = _securityAlgorithmSuite.DefaultSymmetricKeyLength;
                    keyType = WsTrustKeyTypes.Symmetric;
                    break;
                case SecurityKeyType.BearerKey:
                    keySize = 0;
                    keyType = WsTrustKeyTypes.Bearer;
                    break;
                default:
                    throw new InvalidOperationException("Invalid key type");
            }

            Entropy entropy = null;
            if (_issuedTokenParameters.KeyType != SecurityKeyType.BearerKey &&
                (KeyEntropyMode == SecurityKeyEntropyMode.ClientEntropy || KeyEntropyMode == SecurityKeyEntropyMode.CombinedEntropy))
            {
                byte[] entropyBytes = new byte[keySize / 8];
                KeyGenerator.FillRandomBytes(entropyBytes);
                entropy = new Entropy(new BinarySecret(entropyBytes));
            }

            var trustRequest = new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue)
            {
                AppliesTo = new AppliesTo(new EndpointReference(target.Uri.OriginalString)),
                Context = RequestContext,
                KeySizeInBits = keySize,
                KeyType = keyType,
                RequestType = WsTrustActions.Issue,
                TokenType = SecurityTokenRequirement.TokenType,
                WsTrustVersion = WsTrustVersion
            };

            if (entropy != null)
                trustRequest.Entropy = entropy;

            return trustRequest;
        }

        /// <summary>
        /// Gets the <see cref="SecurityTokenRequirement"/>
        /// </summary>
        public SecurityTokenRequirement SecurityTokenRequirement
        {
            get;
        }

        /// <summary>
        /// Gets a string used as a context sent in WsTrustRequests that is useful for correlating requests.
        /// </summary>
        public string RequestContext
        {
            get;
        }

        /// <summary>
        /// Gets or sets the cached security token response
        /// </summary>
        private WsTrustResponse CachedResponse
        {
            // TODO : At some point, it may be valuable to replace this with a cache (Microsoft.Extensions.Caching.Distributed.IDistributedCache, perhaps)
            //        so that caches can be shared between token providers. For the time being, this is just an in-memory WsTrustResponse since a
            //        WSTrustChannelSecurityTokenProvider will only ever use a single WsTrustRequest. If caches can be shared, though, then this would
            //        be replaced with a more full-featured cache allowing multiple providers to cache tokens in a single cache object.
            get;
            set;
        }

        /// <summary>
        /// Gets or sets whether issued tokens should be cached and reused within their expiry periods.
        /// </summary>
        public bool CacheIssuedTokens { get; set; } = DefaultCacheIssuedTokens;

        /// <summary>
        /// Gets or sets the maximum time an issued token will be cached before renewing it.
        /// </summary>
        public TimeSpan MaxIssuedTokenCachingTime
        {
            get => _maxIssuedTokenCachingTime;
            set => _maxIssuedTokenCachingTime = value <= TimeSpan.Zero
                ? throw new ArgumentOutOfRangeException(nameof(value), "TimeSpan must be greater than TimeSpan.Zero.") // TODO - Get exception messages from resources
                : value;
        }

        /// <summary>
        /// Gets or sets the version of message security protocols to use.
        /// </summary>
        public MessageSecurityVersion MessageSecurityVersion
        {
            get => _messageSecurityVersion;
            set => _messageSecurityVersion = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the issuer binding from the issued token parameters.
        /// </summary>
        public Binding IssuerBinding
        {
            get => _issuedTokenParameters?.IssuerBinding;
        }

        /// <summary>
        /// Gets or sets the percentage of the issued token's lifetime at which it should be renewed instead of cached.
        /// </summary>
        public int IssuedTokenRenewalThresholdPercentage
        {
            get => _issuedTokenRenewalThresholdPercentage;
            set => _issuedTokenRenewalThresholdPercentage = (value <= 0 || value > 100)
                ? throw new ArgumentOutOfRangeException(nameof(value), "Issued token renewal threshold percentage must be greater than or equal to 1 and less than or equal to 100.")
                : value;
        }

        /// <summary>
        /// Gets or sets the desired key entroy mode to use when making requests to the STS.
        /// </summary>
        public SecurityKeyEntropyMode KeyEntropyMode
        {
            get => _keyEntropyMode;
            set
            {
                if (!Enum.IsDefined(typeof(SecurityKeyEntropyMode), value))
                    throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(SecurityKeyEntropyMode));

                _keyEntropyMode = value;
            }
        }

        /// <summary>
        /// Gets the WsTrustVersion for the current MessageSecurityVersion.
        /// </summary>
        private WsTrustVersion WsTrustVersion
        {
            get
            {
                TrustVersion trustVersion = MessageSecurityVersion.TrustVersion;

                if (trustVersion == TrustVersion.WSTrust13)
                {
                    return WsTrustVersion.Trust13;
                }

                if (trustVersion == TrustVersion.WSTrustFeb2005)
                {
                    return WsTrustVersion.TrustFeb2005;
                }

                throw new ArgumentException("Unsupported trust version");
            }
        }

        /// <summary>
        /// Gets the WsTrustKeyTypes for the current MessageSecurityVersion.
        /// </summary>
        private WsTrustKeyTypes WsTrustKeyTypes
        {
            get
            {
                WsTrustVersion version = WsTrustVersion;
                if (version is WsTrust14Version)
                {
                    return WsTrustKeyTypes.Trust14;
                }
                if (version is WsTrust13Version)
                {
                    return WsTrustKeyTypes.Trust13;
                }
                if (version is WsTrustFeb2005Version)
                {
                    return WsTrustKeyTypes.TrustFeb2005;
                }

                throw new ArgumentException("Unsupported trust version");
            }
        }

        /// <summary>
        /// Gets the WsTrustActions for the current MessageSecurityVersion.
        /// </summary>
        private WsTrustActions WsTrustActions
        {
            get
            {
                WsTrustVersion version = WsTrustVersion;
                if (version is WsTrust14Version)
                {
                    return WsTrustActions.Trust14;
                }
                if (version is WsTrust13Version)
                {
                    return WsTrustActions.Trust13;
                }
                if (version is WsTrustFeb2005Version)
                {
                    return WsTrustActions.TrustFeb2005;
                }

                throw new ArgumentException("Unsupported trust version");
            }
        }

        private WsTrustResponse GetCachedResponse(WsTrustRequest request)
        {
            if (CacheIssuedTokens && CachedResponse != null)
            {
                // If cached responses are read from shared caches in the future, then that cache should be read here
                // and, if necessary, translated (perhaps via deserialization) into a WsTrustResponse.
                if (!IsWsTrustResponseExpired(CachedResponse))
                    return CachedResponse;
            }

            return null;
        }

        private void CacheSecurityTokenResponse(WsTrustRequest request, WsTrustResponse response)
        {
            if (CacheIssuedTokens)
            {
                // If cached respones are stored in a shared cache in the future, that cache should be written
                // to here, possibly including serializing the WsTrustResponse if the cache stores byte[] (as
                // IDistributedCache does).
                CachedResponse = response;
            }
        }

        private bool IsWsTrustResponseExpired(WsTrustResponse response)
        {
            Lifetime responseLifetime = response?.RequestSecurityTokenResponseCollection?[0]?.Lifetime;

            if (responseLifetime == null || responseLifetime.Expires == null)
            {
                // A null lifetime could represent an invalid response or a valid response
                // with an unspecified expiration. Similarly, a response lifetime without an expiration
                // time represents an unspecified expiration. In any of these cases, err on the side of
                // retrieving a new response instead of possibly using an invalid or expired one.
                return true;
            }

            // If a response's lifetime doesn't specify a created time, conservatively assume the response was just created.
            DateTime fromTime = responseLifetime.Created?.ToUniversalTime() ?? DateTime.UtcNow;
            DateTime toTime = responseLifetime.Expires.Value.ToUniversalTime();

            long interval = toTime.Ticks - fromTime.Ticks;
            long effectiveInterval = (long)((IssuedTokenRenewalThresholdPercentage / (double)100) * interval);
            DateTime effectiveExpiration = AddTicks(fromTime, Math.Min(effectiveInterval, MaxIssuedTokenCachingTime.Ticks));

            return effectiveExpiration < DateTime.UtcNow;
        }

        private DateTime AddTicks(DateTime time, long ticks)
        {
            if (ticks > 0 && DateTime.MaxValue.Subtract(time).Ticks <= ticks)
                return DateTime.MaxValue;

            if (ticks < 0 && time.Subtract(DateTime.MinValue).Ticks <= -ticks)
                return DateTime.MinValue;

            return time.AddTicks(ticks);
        }

        /// <summary>
        /// Calls out to the STS, if necessary to get a token
        /// </summary>
        protected override IdentityModel.Tokens.SecurityToken GetTokenCore(TimeSpan timeout)
        {
            WsTrustRequest request = CreateWsTrustRequest();
            WsTrustResponse trustResponse = GetCachedResponse(request);
            if (trustResponse is null)
            {
                using (var memeoryStream = new MemoryStream())
                {
                    var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                    var serializer = new WsTrustSerializer();
                    serializer.WriteRequest(writer, WsTrustVersion, request);
                    writer.Flush();
                    var reader = XmlDictionaryReader.CreateTextReader(memeoryStream.ToArray(), XmlDictionaryReaderQuotas.Max);

                    IRequestChannel channel = _channelFactory.CreateChannel();
                    Message reply = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.IssueRequest, reader));
                    trustResponse = serializer.ReadResponse(reply.GetReaderAtBodyContents());

                    CacheSecurityTokenResponse(request, trustResponse);
                }
            }

            // Create GenericXmlSecurityToken
            // Assumes that token is first and Saml2SecurityToken.
            using (var stream = new MemoryStream())
            {
                RequestSecurityTokenResponse response = trustResponse.RequestSecurityTokenResponseCollection[0];

                // Get security token
                var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
                var tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.TryWriteSourceData(writer, response.RequestedSecurityToken.SecurityToken);
                writer.Flush();
                stream.Seek(0, SeekOrigin.Begin);
                var dom = new XmlDocument
                {
                    PreserveWhitespace = true
                };

                dom.Load(new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit });

                // Get attached and unattached references
                GenericXmlSecurityKeyIdentifierClause internalSecurityKeyIdentifierClause = null;
                if (response.AttachedReference != null)
                    internalSecurityKeyIdentifierClause = GetSecurityKeyIdentifierForTokenReference(response.AttachedReference);

                GenericXmlSecurityKeyIdentifierClause externalSecurityKeyIdentifierClause = null;
                if (response.UnattachedReference != null)
                    externalSecurityKeyIdentifierClause = GetSecurityKeyIdentifierForTokenReference(response.UnattachedReference);

                // Get proof token
                IdentityModel.Tokens.SecurityToken proofToken = GetProofToken(request, response);

                // Get lifetime
                DateTime created = response.Lifetime?.Created ?? DateTime.UtcNow;
                DateTime expires = response.Lifetime?.Expires ?? created.AddDays(1);

                return new GenericXmlSecurityToken(dom.DocumentElement,
                                                   proofToken,
                                                   created,
                                                   expires,
                                                   internalSecurityKeyIdentifierClause,
                                                   externalSecurityKeyIdentifierClause,
                                                   null);
            }
        }

        private GenericXmlSecurityKeyIdentifierClause GetSecurityKeyIdentifierForTokenReference(SecurityTokenReference tokenReference)
        {
            if (tokenReference == null)
                return null;

            SecurityTokenReference securityTokenReference = new SecurityTokenReference
            {
                Id = tokenReference.KeyIdentifier.Value,
                TokenType = tokenReference.TokenType
            };
            return new GenericXmlSecurityKeyIdentifierClause(WsSecuritySerializer.GetXmlElement(securityTokenReference, WsTrustVersion));
        }

        /// <summary>
        /// Get a proof token from a WsTrust request/response pair based on section 4.4.3 of the WS-Trust 1.3 spec.
        /// How the proof token is retrieved depends on whether the requestor or issuer provide key material:
        /// Requestor   |   Issuer                  | Results
        /// -------------------------------------------------
        /// Entropy     | No key material           | No proof token returned, requestor entropy used
        /// Entropy     | Entropy                   | Computed key algorithm returned and key computed based on request and response entropy
        /// Entropy     | Rejects requestor entropy | Proof token in response used as key
        /// No entropy  | Issues key                | Proof token in response used as key
        /// No entropy  | No key material           | No proof token
        /// </summary>
        /// <param name="request">The WS-Trust request (RST).</param>
        /// <param name="response">The WS-Trust response (RSTR).</param>
        /// <returns>The proof token or null if there is no proof token.</returns>
        private BinarySecretSecurityToken GetProofToken(WsTrustRequest request, RequestSecurityTokenResponse response)
        {
            // According to the WS-Trust 1.3 spec, symmetric is the default key type
            string keyType = response.KeyType ?? request.KeyType ?? WsTrustKeyTypes.Symmetric;

            // Encrypted keys and encrypted entropy are not supported, currently, as they should
            // only be needed by unsupported message security scenarios.
            if (response.RequestedProofToken?.EncryptedKey != null)
                throw new NotSupportedException("Encrypted keys for proof tokens are not supported.");

            // Bearer scenarios have no proof token
            if (string.Equals(keyType, WsTrustKeyTypes.Bearer, StringComparison.Ordinal))
            {
                if (response.RequestedProofToken != null || response.Entropy != null)
                    throw new InvalidOperationException("Bearer key scenarios should not include a proof token or issuer entropy in the response.");

                return null;
            }

            // If the response includes a proof token, use it as the security token's proof.
            // This scenario will occur if the request does not include entropy or if the issuer rejects the requestor's entropy.
            if (response.RequestedProofToken?.BinarySecret != null)
            {
                // Confirm that a computed key algorithm isn't also specified
                if (!string.IsNullOrEmpty(response.RequestedProofToken.ComputedKeyAlgorithm) || response.Entropy != null)
                    throw new InvalidOperationException("An RSTR containing a proof token should not also have a computed key algorithm or issuer entropy.");

                return new BinarySecretSecurityToken(response.RequestedProofToken.BinarySecret.Data);
            }
            // If the response includes a computed key algorithm, compute the proof token based on requestor and issuer entropy.
            // This scenario will occur if the requestor and issuer both provide key material.
            else if (response.RequestedProofToken?.ComputedKeyAlgorithm != null)
            {
                if (!string.Equals(keyType, WsTrustKeyTypes.Symmetric, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Computed key proof tokens are only supported with symmetric key types.");
                }

                if (string.Equals(response.RequestedProofToken.ComputedKeyAlgorithm, WsTrustKeyTypes.PSHA1, StringComparison.Ordinal))
                {
                    // Confirm that no encrypted entropy was provided as that is currently not supported.
                    // If we wish to support it in the future, most of the work will be in the WSTrust serializer;
                    // this code would just have to use protected key's .Secret property to get the key material.
                    if (response.Entropy?.ProtectedKey != null || request.Entropy?.ProtectedKey != null)
                        throw new NotSupportedException("Protected key entropy is not supported.");

                    // Get issuer and requestor entropy
                    byte[] issuerEntropy = response.Entropy?.BinarySecret?.Data;
                    if (issuerEntropy == null)
                        throw new InvalidOperationException("Computed key proof tokens require issuer to supply key material via entropy.");

                    byte[] requestorEntropy = request.Entropy?.BinarySecret?.Data;
                    if (requestorEntropy == null)
                        throw new InvalidOperationException("Computed key proof tokens require requestor to supply key material via entropy.");

                    // Get key size
                    int keySizeInBits = response.KeySizeInBits ?? 0; // RSTR key size has precedence
                    if (keySizeInBits == 0)
                        keySizeInBits = request.KeySizeInBits ?? 0; // Followed by RST

                    if (keySizeInBits == 0)
                        keySizeInBits = _securityAlgorithmSuite?.DefaultSymmetricKeyLength ?? 0; // Symmetric keys should default to a length cooresponding to the algorithm in use

                    if (keySizeInBits == 0)
                        throw new InvalidOperationException("No key size provided.");

                    return new BinarySecretSecurityToken(KeyGenerator.ComputeCombinedKey(issuerEntropy, requestorEntropy, keySizeInBits));
                }
                else
                {
                    throw new NotSupportedException("Only PSHA1 computed keys are supported.");
                }
            }
            // If the response does not have a proof token or computed key value, but the request proposed entropy,
            // then the requestor's entropy is used as the proof token.
            else if (request.Entropy != null)
            {
                if (request.Entropy.ProtectedKey != null)
                    throw new NotSupportedException("Protected key entropy is not supported.");

                if (request.Entropy.BinarySecret != null)
                    return new BinarySecretSecurityToken(request.Entropy.BinarySecret.Data);
            }

            // If we get here, then no key material has been supplied (by either issuer or requestor), so there is no proof token.
            return null;
        }
    }
}
