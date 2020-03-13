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
        private ISecurityTokenResponseCache<WsTrustRequest, WsTrustResponse> _cache;
        private readonly WsTrustRequest _wsTrustRequest;
        private readonly ChannelFactory<IRequestChannel> _channelFactory;

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            SecurityTokenRequirement = tokenRequirement ?? throw new ArgumentNullException(nameof(tokenRequirement));
            _cache = new InMemorySecurityTokenResponseCache<WsTrustRequest, WsTrustResponse>(new WsTrustRequestComparer());

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

            // Note that WsTrustRequestComparer needs to compare any properties that are set here. If WsTrustRequest creation logic changes here, update WsTrustRequestComparer accordingly.
            return new WsTrustRequest()
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
        public ISecurityTokenResponseCache<WsTrustRequest, WsTrustResponse> IssuedTokensCache
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
                WsTrustResponse response = IssuedTokensCache?.GetSecurityTokenResponse(request);
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

            long interval = fromTime.Ticks - toTime.Ticks;
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
                IssuedTokensCache?.CacheSecurityTokenResponse(request, response);
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

                    var channel = _channelFactory.CreateChannel();
                    var reply = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressing10, WsTrustActions.Trust13.IssueRequest, reader));
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
        /// This comparer determines whether two WsTrustRequests prepared by WsTrustChannelSecurityTokenProvider.
        /// In the interest of simplicity and performance, it is not a general-purpose WsTrustRequest comparer. Instead,
        /// this type compares properties known to be of interest to WsTrustChannelSecurityTokenProvider
        /// </summary>
        private class WsTrustRequestComparer : IEqualityComparer<WsTrustRequest>
        {
            public bool Equals(WsTrustRequest request, WsTrustRequest otherRequest)
            {
                if (request is null)
                {
                    return otherRequest is null;
                }

                if (otherRequest is null)
                {
                    return false;
                }

                if (!string.Equals(request.RequestType, otherRequest.RequestType, StringComparison.Ordinal) ||
                    !string.Equals(request.Context, otherRequest.Context, StringComparison.Ordinal) ||
                    !string.Equals(request.TokenType, otherRequest.TokenType, StringComparison.Ordinal) ||
                    !string.Equals(request.KeyType, otherRequest.KeyType, StringComparison.Ordinal) ||
                    (!request.AppliesTo.EndpointReference?.Uri.Equals(otherRequest.AppliesTo.EndpointReference?.Uri) ?? (otherRequest.AppliesTo.EndpointReference is null)))
                {
                    return false;
                }

                return true;
            }

            public int GetHashCode(WsTrustRequest request) =>
                request.RequestType?.GetHashCode() ?? "NoRequestType".GetHashCode()
                ^ request.Context?.GetHashCode() ?? "NoContext".GetHashCode()
                ^ request.AppliesTo.EndpointReference?.Uri.GetHashCode() ?? "NoAppliesToEndpoint".GetHashCode()
                ^ request.TokenType?.GetHashCode() ?? "NoTokenType".GetHashCode()
                ^ request.KeyType?.GetHashCode() ?? "NoKeyType".GetHashCode();
        }
    }
}
