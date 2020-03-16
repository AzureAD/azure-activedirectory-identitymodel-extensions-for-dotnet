// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.ServiceModel.Channels;
using System.ServiceModel.Caching;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace System.ServiceModel.Federation
{

    /// <summary>
    /// Custom WSTrustChannelSecurityTokenProvider that returns a SAML assertion
    /// </summary>
    public class WSTrustChannelSecurityTokenProvider : SecurityTokenProvider
    {
        internal const bool DefaultCacheIssuedTokens = true;
        internal static readonly TimeSpan DefaultMaxIssuedTokenCachingTime = TimeSpan.MaxValue;
        internal const int DefaultIssuedTokenRenewalThresholdPercentage = 60;

        private TimeSpan _maxIssuedTokenCachingTime = DefaultMaxIssuedTokenCachingTime;
        private int _issuedTokenRenewalThresholdPercentage = DefaultIssuedTokenRenewalThresholdPercentage;
        private ISecurityTokenResponseCache<WsTrustRequestKey, WsTrustResponse> _cache;
        private readonly WsTrustRequest _wsTrustRequest;
        private readonly ChannelFactory<IRequestChannel> _channelFactory;

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            SecurityTokenRequirement = tokenRequirement ?? throw new ArgumentNullException(nameof(tokenRequirement));
            _cache = new InMemorySecurityTokenResponseCache<WsTrustRequestKey, WsTrustResponse>(EqualityComparer<WsTrustRequestKey>.Default);

            IssuedSecurityTokenParameters issuedTokenParameters = SecurityTokenRequirement.GetProperty<IssuedSecurityTokenParameters>("http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters");

            _wsTrustRequest = CreateWsTrustRequest(issuedTokenParameters);
            _channelFactory = CreateChannelFactory(issuedTokenParameters);
        }

        protected virtual ChannelFactory<IRequestChannel> CreateChannelFactory(IssuedSecurityTokenParameters issuedTokenParameters)
        {
            var factory = new ChannelFactory<IRequestChannel>(issuedTokenParameters.IssuerBinding, issuedTokenParameters.IssuerAddress);

            // Temporary as test STS is not trusted.
            // This code should be removed.
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication();
            factory.Credentials.ServiceCertificate.SslCertificateAuthentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

            return factory;
        }

        private WsTrustRequest CreateWsTrustRequest(IssuedSecurityTokenParameters issuedTokenParameters)
        {
            EndpointAddress target = SecurityTokenRequirement.GetProperty<EndpointAddress>("http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/TargetAddress");

            // Note that WsTrustRequestKey needs to capture any properties that are set here. If WsTrustRequest creation logic changes here, update WsTrustRequestKey accordingly.
            return new WsTrustRequest(WsTrustConstants.Trust13.WsTrustActions.Issue)
            {
                AppliesTo = new AppliesTo(new EndpointReference(target.Uri.OriginalString)),
                Context = Guid.NewGuid().ToString(),
                KeyType = issuedTokenParameters.KeyType == SecurityKeyType.AsymmetricKey
                                                        ? WsTrustKeyTypes.Trust13.PublicKey
                                                        : issuedTokenParameters.KeyType == SecurityKeyType.SymmetricKey
                                                        ? WsTrustKeyTypes.Trust13.Symmetric
                                                        : WsTrustKeyTypes.Trust13.Bearer,
                //ProofEncryption = new Microsoft.IdentityModel.Xml.SecurityTokenElement()
                RequestType = WsTrustConstants.Trust13.WsTrustActions.Issue,
                TokenType = SecurityTokenRequirement.TokenType
            };
        }

        public SecurityTokenRequirement SecurityTokenRequirement
        {
            get;
        }

        /// <summary>
        /// Gets or sets the cache used for storing issued security tokens.
        /// </summary>
        public ISecurityTokenResponseCache<WsTrustRequestKey, WsTrustResponse> IssuedTokensCache
        {
            get => _cache;
            set => _cache = value ?? throw new ArgumentNullException(nameof(value));
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
        /// Gets or sets the percentage of the issued token's lifetime at which it should be renewed instead of cached.
        /// </summary>
        public int IssuedTokenRenewalThresholdPercentage
        {
            get => _issuedTokenRenewalThresholdPercentage;
            set => _issuedTokenRenewalThresholdPercentage = (value <= 0 || value > 100)
                ? throw new ArgumentOutOfRangeException(nameof(value), "Issued token renewal threshold percentage must be greater than or equal to 1 and less than or equal to 100.")
                : value;
        }

        public string TokenContext
        {
            get => _wsTrustRequest.Context;
            set => _wsTrustRequest.Context = value;
        }

        private WsTrustResponse GetCachedResponse(WsTrustRequest request)
        {
            if (CacheIssuedTokens)
            {
                WsTrustResponse response = IssuedTokensCache?.GetSecurityTokenResponse(new WsTrustRequestKey(request));
                if (IsSecurityTokenResponseUnexpired(response))
                {
                    return response;
                }
            }

            return null;
        }

        private bool IsSecurityTokenResponseUnexpired(WsTrustResponse cachedResponse)
        {
            var cachedToken = cachedResponse?.RequestSecurityTokenResponseCollection?[0]?.RequestedSecurityToken?.SecurityToken;

            if (cachedToken == null)
            {
                return false;
            }

            DateTime fromTime = cachedToken.ValidFrom.ToUniversalTime();
            DateTime toTime = cachedToken.ValidTo.ToUniversalTime();

            long interval = toTime.Ticks - fromTime.Ticks;
            long effectiveInterval = (long)((IssuedTokenRenewalThresholdPercentage / (double)100) * interval);
            DateTime effectiveExpiration = AddTicks(fromTime, Math.Min(effectiveInterval, MaxIssuedTokenCachingTime.Ticks));

            return effectiveExpiration > DateTime.UtcNow;
        }

        private DateTime AddTicks(DateTime time, long ticks)
        {
            if (ticks > 0 && DateTime.MaxValue.Subtract(time).Ticks <= ticks)
            {
                return DateTime.MaxValue;
            }
            if (ticks < 0 && time.Subtract(DateTime.MinValue).Ticks <= -ticks)
            {
                return DateTime.MinValue;
            }
            return time.AddTicks(ticks);
        }

        private void CacheSecurityTokenResponse(WsTrustRequest request, WsTrustResponse response)
        {
            if (CacheIssuedTokens)
            {
                IssuedTokensCache?.CacheSecurityTokenResponse(new WsTrustRequestKey(request), response);
            }
        }

        /// <summary>
        /// Calls out to the STS, if necessary to get a token
        /// </summary>
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            WsTrustResponse trustResponse = GetCachedResponse(_wsTrustRequest);
            if (trustResponse is null)
            {
                using (var memeoryStream = new MemoryStream())
                {
                    var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                    var serializer = new WsTrustSerializer();
                    serializer.WriteRequest(writer, WsTrustVersion.Trust13, _wsTrustRequest);
                    writer.Flush();
                    var reader = XmlDictionaryReader.CreateTextReader(memeoryStream.ToArray(), XmlDictionaryReaderQuotas.Max);

                    IRequestChannel channel = _channelFactory.CreateChannel();
                    Message reply = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.Trust13.IssueRequest, reader));
                    trustResponse = serializer.ReadResponse(reply.GetReaderAtBodyContents());

                    CacheSecurityTokenResponse(_wsTrustRequest, trustResponse);
                }
            }

            // Create GenericXmlSecurityToken
            // Assumes that token is first and Saml2SecurityToken.
            using (var stream = new MemoryStream())
            {
                var response = trustResponse.RequestSecurityTokenResponseCollection[0];
                var writer = XmlDictionaryWriter.CreateTextWriter(stream, Encoding.UTF8, false);
                var tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.TryWriteSourceData(writer, response.RequestedSecurityToken.SecurityToken);
                writer.Flush();
                stream.Seek(0, SeekOrigin.Begin);
                var dom = new XmlDocument
                {
                    PreserveWhitespace = true
                };

                BinarySecretSecurityToken proofToken = null;
                if (trustResponse.RequestSecurityTokenResponseCollection[0].RequestedProofToken != null)
                    proofToken = new BinarySecretSecurityToken(trustResponse.RequestSecurityTokenResponseCollection[0].RequestedProofToken.BinarySecret.Data);

                WsSecuritySerializer wsSecuritySerializer = new WsSecuritySerializer();
                SecurityTokenReference securityTokenReference = new SecurityTokenReference
                {
                    Id = response.AttachedReference.KeyIdentifier.Value,
                    TokenType = response.AttachedReference.TokenType
                };

                var element = WsSecuritySerializer.GetXmlElement(securityTokenReference, WsTrustVersion.Trust13);
                dom.Load(new XmlTextReader(stream) { DtdProcessing = DtdProcessing.Prohibit });
                GenericXmlSecurityKeyIdentifierClause securityKeyIdentifierClause = new GenericXmlSecurityKeyIdentifierClause(element);
                var securityToken = new GenericXmlSecurityToken(dom.DocumentElement,
                                                   proofToken,
                                                   DateTime.UtcNow,
                                                   DateTime.UtcNow + TimeSpan.FromDays(1),
                                                   securityKeyIdentifierClause,
                                                   securityKeyIdentifierClause,
                                                   null);

                return securityToken;
            }
        }

        /// <summary>
        /// This immutable type is used as a key in WSTrustChannelSecurityTokenProvider response caches. Using this
        /// type as the key (instead of WsTrustRequest directly) prevents responses' keys from changing after the responses
        /// have been cached. It also make it easy to store and compare only the properties of WsTrustRequest that are of
        /// interest to WsTrustChannelSecurityTokenProvider.
        /// </summary>
        public class WsTrustRequestKey
        {
            private readonly string _requestType;
            private readonly string _context;
            private readonly string _tokenType;
            private readonly string _keyType;
            private readonly string _appliesToUri;

            public WsTrustRequestKey(WsTrustRequest request)
            {
                _requestType = request.RequestType;
                _context = request.Context;
                _tokenType = request.TokenType;
                _keyType = request.KeyType;
                _appliesToUri = request.AppliesTo?.EndpointReference?.Uri.ToString();
            }

            public override bool Equals(object obj)
            {
                if (!(obj is WsTrustRequestKey other))
                {
                    return false;
                }

                return string.Equals(_requestType, other._requestType, StringComparison.Ordinal) &&
                    string.Equals(_context, other._context, StringComparison.Ordinal) &&
                    string.Equals(_tokenType, other._tokenType, StringComparison.Ordinal) &&
                    string.Equals(_keyType, other._keyType, StringComparison.Ordinal) &&
                    string.Equals(_appliesToUri, other._appliesToUri, StringComparison.Ordinal);
            }

            public override int GetHashCode() =>
                _requestType?.GetHashCode() ?? "NoRequestType".GetHashCode()
                ^ _context?.GetHashCode() ?? "NoContext".GetHashCode()
                ^ _appliesToUri?.GetHashCode() ?? "NoAppliesToEndpoint".GetHashCode()
                ^ _tokenType?.GetHashCode() ?? "NoTokenType".GetHashCode()
                ^ _keyType?.GetHashCode() ?? "NoKeyType".GetHashCode();
        }
    }
}
