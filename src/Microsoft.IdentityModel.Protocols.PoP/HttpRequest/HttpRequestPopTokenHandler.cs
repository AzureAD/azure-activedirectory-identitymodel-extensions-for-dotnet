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

using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.PoP.HttpRequest
{
    using ClaimTypes = PopConstants.HttpRequest.ClaimTypes;

    /// <summary>
    /// 
    /// </summary>
    public class HttpRequestPopTokenHandler : IHttpRequestPopTokenCreator, IHttpRequestPopTokenValidator
    {
        private readonly JsonWebTokenHandler _jwtTokenHandler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();
        private readonly string _newlineSeparator = "\n";

        #region PoP token creation
        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenWithCnfClaim"></param>
        /// <param name="signingCredentials"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popTokenCreationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<string> CreatePopTokenAsync(string tokenWithCnfClaim, SigningCredentials signingCredentials, HttpRequestData httpRequestData, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy, CancellationToken cancellationToken)
        {
            var header = CreatePopTokenHeader(signingCredentials, popTokenCreationPolicy);
            var payload = CreatePopTokenPayload(tokenWithCnfClaim, httpRequestData, popTokenCreationPolicy);
            return await SignPopTokenAsync(header, payload, signingCredentials, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signingCredentials"></param>
        /// <param name="popTokenCreationPolicy"></param>
        /// <returns></returns>
        protected virtual string CreatePopTokenHeader(SigningCredentials signingCredentials, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, signingCredentials.Algorithm },
                { JwtHeaderParameterNames.Typ, PopConstants.HttpRequest.PopTokenType }
            };

            if (signingCredentials.Key?.KeyId != null)
                header.Add(JwtHeaderParameterNames.Kid, signingCredentials.Key.KeyId);

            if (signingCredentials.Key is X509SecurityKey x509SecurityKey)
                header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;

            return header.ToString(Formatting.None);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenWithCnfClaim"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popTokenCreationPolicy"></param>
        /// <returns></returns>
        protected internal virtual string CreatePopTokenPayload(string tokenWithCnfClaim, HttpRequestData httpRequestData, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (popTokenCreationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenCreationPolicy));

            Dictionary<string, object> payload = new Dictionary<string, object>();

            AddAtClaim(payload, tokenWithCnfClaim, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateTs)
                AddTsClaim(payload, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateM)
                AddMClaim(payload, httpRequestData?.HttpMethod, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateU)
                AddUClaim(payload, httpRequestData?.HttpRequestUri, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateP)
                AddPClaim(payload, httpRequestData?.HttpRequestUri, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateQ)
                AddQClaim(payload, httpRequestData?.HttpRequestUri, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateH)
                AddHClaim(payload, httpRequestData?.HttpRequestHeaders, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateB)
                AddBClaim(payload, httpRequestData?.HttpRequestBody, popTokenCreationPolicy);

            if (popTokenCreationPolicy.CreateNonce)
                AddNonceClaim(payload, popTokenCreationPolicy);

            popTokenCreationPolicy.CustomClaimCreator?.Invoke(tokenWithCnfClaim, payload, httpRequestData, popTokenCreationPolicy);

            return JObject.FromObject(payload).ToString(Formatting.None);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="signingCredentials"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual Task<string> SignPopTokenAsync(string header, string payload, SigningCredentials signingCredentials, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var message = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))}";
            var signature = JwtTokenUtilities.CreateEncodedSignature(message, signingCredentials);
            return Task.FromResult($"{message}.{signature}");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="tokenWithCnfClaim"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddAtClaim(Dictionary<string, object> payload, string tokenWithCnfClaim, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrEmpty(tokenWithCnfClaim))
                throw LogHelper.LogArgumentNullException(nameof(tokenWithCnfClaim));

            payload.Add(ClaimTypes.At, tokenWithCnfClaim);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddTsClaim(Dictionary<string, object> payload, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (popTokenCreationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenCreationPolicy));

            var popTokenCreationTime = DateTime.UtcNow.Add(popTokenCreationPolicy.ClockSkew);
            payload.Add(ClaimTypes.Ts, (long)(popTokenCreationTime - EpochTime.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpMethod"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddMClaim(Dictionary<string, object> payload, string httpMethod, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrEmpty(httpMethod))
                throw LogHelper.LogArgumentNullException(nameof(httpMethod));

            if (!httpMethod.ToUpper().Equals(httpMethod, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

            payload.Add(ClaimTypes.M, httpMethod);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddUClaim(Dictionary<string, object> payload, Uri httpRequestUri, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
            // u claim: The HTTP URL host component as a JSON string. This MAY include the port separated from the host by a colon in host:port format.
            // Including the port if it not the default port for the httpRequestUri scheme.
            var httpUrlHostComponent = httpRequestUri.Host;
            if (!httpRequestUri.IsDefaultPort)
                httpUrlHostComponent = $"{httpUrlHostComponent}:{httpRequestUri.Port}";

            payload.Add(ClaimTypes.U, httpUrlHostComponent);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddPClaim(Dictionary<string, object> payload, Uri httpRequestUri, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            // value is normalized by always omitting the trailing '/'
            payload.Add(ClaimTypes.P, httpRequestUri.AbsolutePath.TrimEnd('/'));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddQClaim(Dictionary<string, object> payload, Uri httpRequestUri, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> queryParamNameList = new List<string>();
            try
            {
                var lastQueryParam = sanitizedQueryParams.Last();
                foreach (var queryParam in sanitizedQueryParams)
                {
                    queryParamNameList.Add(queryParam.Key);
                    var encodedValue = $"{queryParam.Key}={queryParam.Value}";

                    if (!queryParam.Equals(lastQueryParam))
                        encodedValue += "&";

                    stringBuffer.Append(encodedValue);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(ClaimTypes.Q, new List<object>() { queryParamNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.Q, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddHClaim(Dictionary<string, object> payload, IDictionary<string, IEnumerable<string>> httpRequestHeaders, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            var sanitizedHeaders = SanitizeHeaders(httpRequestHeaders);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> headerNameList = new List<string>();
            try
            {
                var lastHeader = sanitizedHeaders.Last();
                foreach (var header in sanitizedHeaders)
                {
                    var headerName = header.Key.ToLowerInvariant();
                    headerNameList.Add(headerName);

                    var encodedValue = $"{headerName}: {header.Value}";
                    if (header.Equals(lastHeader))
                        stringBuffer.Append(encodedValue);
                    else
                        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
                        // Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character.
                        //
                        // GK: The spec holds a wrong example of the hash. Value "bZA981YJBrPlIzOvplbu3e7ueREXXr38vSkxIBYOaxI" is calculated using the "\r\n" separator, and not "\n".
                        // Spec authors probably used Environment.NewLine or stringBuilder.AppendLine which appends "\r\n" on non-Unix platforms.
                        // The correct hash value should be "P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs".
                        stringBuffer.Append(encodedValue + _newlineSeparator);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(ClaimTypes.H, new List<object>() { headerNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.H, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestBody"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddBClaim(Dictionary<string, object> payload, byte[] httpRequestBody, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            try
            {
                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
                payload.Add(ClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="popTokenCreationPolicy"></param>
        protected virtual void AddNonceClaim(Dictionary<string, object> payload, HttpRequestPopTokenCreationPolicy popTokenCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (popTokenCreationPolicy.NonceClaimCreator != null)
                popTokenCreationPolicy.NonceClaimCreator(payload, popTokenCreationPolicy);
            else
                payload.Add(ClaimTypes.Nonce, Guid.NewGuid().ToString("N"));
        }
        #endregion

        #region PoP token validation
        /// <summary>
        /// 
        /// </summary>
        /// <param name="popToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<HttpRequestPopTokenValidationResult> ValidatePopTokenAsync(string popToken, HttpRequestData httpRequestData, TokenValidationParameters tokenValidationParameters, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(popToken))
                throw LogHelper.LogArgumentNullException(nameof(popToken));

            var jwtPopToken = ReadPopTokenAsJwt(popToken);
            var accessToken = ReadAccessToken(jwtPopToken);
            var tokenValidationResult = await ValidateAccessTokenAsync(accessToken, tokenValidationParameters, cancellationToken).ConfigureAwait(false);
            var validatedAccessToken = tokenValidationResult.SecurityToken as JsonWebToken;
            // use the decrypted jwt if the accessToken is encrypted.
            if (validatedAccessToken.InnerToken != null)
                validatedAccessToken = validatedAccessToken.InnerToken;

            var validatedPopToken = await ValidatePopTokenAsync(jwtPopToken, validatedAccessToken, httpRequestData, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);

            return new HttpRequestPopTokenValidationResult()
            {
                AccessToken = accessToken,
                ClaimsIdentity = tokenValidationResult.ClaimsIdentity,
                ValidatedAccessToken = tokenValidationResult.SecurityToken,
                PopToken = popToken,
                ValidatedPopToken = validatedPopToken
            };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="popToken"></param>
        /// <returns></returns>
        protected virtual JsonWebToken ReadPopTokenAsJwt(string popToken)
        {
            return _jwtTokenHandler.ReadJsonWebToken(popToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <returns></returns>
        protected virtual string ReadAccessToken(JsonWebToken jwtPopToken)
        {
            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.At, out string accessToken) || accessToken == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.At)));

            return accessToken;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, TokenValidationParameters tokenValidationParameters, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            if (tokenValidationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenValidationParameters));

            var tokenValidationResult = _jwtTokenHandler.ValidateToken(accessToken, tokenValidationParameters);

            if (!tokenValidationResult.IsValid)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23013, tokenValidationResult.Exception), tokenValidationResult.Exception));

            return Task.FromResult(tokenValidationResult);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="validatedAccessToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected internal virtual async Task<JsonWebToken> ValidatePopTokenAsync(JsonWebToken jwtPopToken, JsonWebToken validatedAccessToken, HttpRequestData httpRequestData, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (popTokenValidationPolicy.PopTokenReplayValidatorAsync != null)
                await popTokenValidationPolicy.PopTokenReplayValidatorAsync(jwtPopToken, cancellationToken).ConfigureAwait(false);

            await ValidatePopTokenSignatureAsync(jwtPopToken, validatedAccessToken, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);

            if (popTokenValidationPolicy.ValidateTs)
                ValidateTsClaim(jwtPopToken, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateM)
                ValidateMClaim(jwtPopToken, httpRequestData?.HttpMethod, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateU)
                ValidateUClaim(jwtPopToken, httpRequestData?.HttpRequestUri, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateP)
                ValidatePClaim(jwtPopToken, httpRequestData?.HttpRequestUri, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateQ)
                ValidateQClaim(jwtPopToken, httpRequestData?.HttpRequestUri, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateH)
                ValidateHClaim(jwtPopToken, httpRequestData?.HttpRequestHeaders, popTokenValidationPolicy);

            if (popTokenValidationPolicy.ValidateB)
                ValidateBClaim(jwtPopToken, httpRequestData?.HttpRequestBody, popTokenValidationPolicy);

            if (popTokenValidationPolicy.CustomClaimValidatorAsync != null)
                await popTokenValidationPolicy.CustomClaimValidatorAsync(jwtPopToken, validatedAccessToken, httpRequestData, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);

            return jwtPopToken;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="validatedAccessToken"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        protected virtual async Task ValidatePopTokenSignatureAsync(JsonWebToken jwtPopToken, JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            var popKey = await ResolvePopKeyAsync(validatedAccessToken, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
            if (popKey == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23030)));

            if (popTokenValidationPolicy.PopTokenSignatureValidatorAsync != null)
            {
                await popTokenValidationPolicy.PopTokenSignatureValidatorAsync(popKey, jwtPopToken, validatedAccessToken, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
                return;
            }

            var signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, jwtPopToken.Alg);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23000, popKey?.ToString() ?? "Null", jwtPopToken.Alg ?? "Null")));

            try
            {
                var encodedBytes = Encoding.UTF8.GetBytes(jwtPopToken.EncodedHeader + "." + jwtPopToken.EncodedPayload);
                var signature = Base64UrlEncoder.DecodeBytes(jwtPopToken.EncodedSignature);

                if (!signatureProvider.Verify(encodedBytes, signature))
                    throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009)));
            }
            finally
            {
                popKey.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateTsClaim(JsonWebToken jwtPopToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.Ts, out long tsClaimValue))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Ts)));

            DateTime utcNow = DateTime.UtcNow;
            DateTime popTokenCreationTime = EpochTime.DateTime(tsClaimValue);
            DateTime popTokenExpirationTime = popTokenCreationTime.Add(popTokenValidationPolicy.PopTokenLifetime);

            if (utcNow > popTokenExpirationTime)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23010, utcNow, popTokenExpirationTime)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="expectedHttpMethod"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateMClaim(JsonWebToken jwtPopToken, string expectedHttpMethod, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (string.IsNullOrEmpty(expectedHttpMethod))
                throw LogHelper.LogArgumentNullException(nameof(expectedHttpMethod));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.M, out string httpMethod) || httpMethod == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.M)));

            // "get " is functionally the same as "GET".
            // different implementations might use differently formatted http verbs and we shouldn't fault.
            httpMethod = httpMethod.Trim();
            expectedHttpMethod = expectedHttpMethod.Trim();
            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.M, expectedHttpMethod, httpMethod)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateUClaim(JsonWebToken jwtPopToken, Uri httpRequestUri, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.U, out string uClaimValue) || uClaimValue == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.U)));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2
            // u: The HTTP URL host component as a JSON string.
            // This MAY include the port separated from the host by a colon in host:port format.
            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidatePClaim(JsonWebToken jwtPopToken, Uri httpRequestUri, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.P, out string pClaimValue) || pClaimValue == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.P)));

            // value is normalized by always omitting the trailing '/'
            var expectedPClaimValue = httpRequestUri.AbsolutePath.TrimEnd('/');

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.P, expectedPClaimValue, pClaimValue)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateQClaim(JsonWebToken jwtPopToken, Uri httpRequestUri, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.Q, out JArray qClaim) || qClaim == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Q)));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            string qClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> qClaimQueryParamNames;
            try
            {
                // "q": [["queryParamName1", "queryParamName2",... "queryParamNameN"], "base64UrlEncodedHashValue"]]
                qClaimQueryParamNames = qClaim[0].ToObject<List<string>>();
                qClaimBase64UrlEncodedHash = qClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.Q, qClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastQueryParam = qClaimQueryParamNames.LastOrDefault();
                foreach (var queryParamName in qClaimQueryParamNames)
                {
                    if (!sanitizedQueryParams.TryGetValue(queryParamName, out var queryParamsValue))
                    {
                        throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23028, queryParamName, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{queryParamName}={queryParamsValue}";

                        if (!queryParamName.Equals(lastQueryParam))
                            encodedValue += "&";

                        stringBuffer.Append(encodedValue);

                        // remove the query param from the dictionary to mark it as covered.
                        sanitizedQueryParams.Remove(queryParamName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.Q, e), e));
            }

            if (!popTokenValidationPolicy.AcceptUncoveredQueryParameters && sanitizedQueryParams.Any())
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23029, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.Q, expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateHClaim(JsonWebToken jwtPopToken, IDictionary<string, IEnumerable<string>> httpRequestHeaders, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.H, out JArray hClaim) || hClaim == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.H)));

            var sanitizedHeaders = SanitizeHeaders(httpRequestHeaders);

            string hClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> hClaimHeaderNames;
            try
            {
                // "h": [["headerName1", "headerName2",... "headerNameN"], "base64UrlEncodedHashValue"]]
                hClaimHeaderNames = hClaim[0].ToObject<List<string>>();
                hClaimBase64UrlEncodedHash = hClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.H, hClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastHeader = hClaimHeaderNames.Last();
                foreach (var headerName in hClaimHeaderNames)
                {
                    if (!sanitizedHeaders.TryGetValue(headerName, out var headerValue))
                    {
                        throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23027, headerName, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{headerName}: {headerValue}";
                        if (headerName.Equals(lastHeader))
                            stringBuffer.Append(encodedValue);
                        else
                            stringBuffer.Append(encodedValue + _newlineSeparator);

                        // remove the header from the dictionary to mark it as covered.
                        sanitizedHeaders.Remove(headerName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.H, e), e));
            }

            if (!popTokenValidationPolicy.AcceptUncoveredHeaders && sanitizedHeaders.Any())
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23026, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.H, expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtPopToken"></param>
        /// <param name="httpRequestBody"></param>
        /// <param name="popTokenValidationPolicy"></param>
        protected virtual void ValidateBClaim(JsonWebToken jwtPopToken, byte[] httpRequestBody, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (jwtPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtPopToken));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            if (!jwtPopToken.TryGetPayloadValue(ClaimTypes.B, out string bClaim) || bClaim == null)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.B)));

            string expectedBase64UrlEncodedHash;
            try
            {
                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }

            if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.B, expectedBase64UrlEncodedHash, bClaim)));
        }
        #endregion

        #region Resolving PoP key
        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedAccessToken"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyAsync(JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (popTokenValidationPolicy.PopKeyResolverAsync != null)
                return await popTokenValidationPolicy.PopKeyResolverAsync(validatedAccessToken, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);

            var cnf = JObject.Parse(GetCnfClaimValue(validatedAccessToken, popTokenValidationPolicy));
            if (cnf.TryGetValue(JwtHeaderParameterNames.Jwk, StringComparison.Ordinal, out var jwk))
            {
                return ResolvePopKeyFromJwk(jwk.ToString(), popTokenValidationPolicy);
            }
            else if (cnf.TryGetValue(ClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
            {
                return await ResolvePopKeyFromJweAsync(jwe.ToString(), popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Jku, StringComparison.Ordinal, out var jku))
            {
                if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), kid.ToString(), popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
                else
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
            {
                return await ResolvePopKeyFromKeyIdentifierAsync(kid.ToString(), validatedAccessToken, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23014)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedAccessToken"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <returns></returns>
        protected virtual string GetCnfClaimValue(JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (validatedAccessToken.TryGetPayloadValue(ClaimTypes.Cnf, out JObject cnf) || cnf == null)
                return cnf.ToString();
            else
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Cnf)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwk"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromJwk(string jwk, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy)
        {
            if (string.IsNullOrEmpty(jwk))
                throw LogHelper.LogArgumentNullException(nameof(jwk));

            var jsonWebKey = new JsonWebKey(jwk);

            if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out var key))
            {
                if (key is AsymmetricSecurityKey)
                    return key;
                else
                    throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23015, key.GetType().ToString())));
            }
            else
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23016, jsonWebKey.Kid ?? "Null")));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwe"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            var jsonWebToken = _jwtTokenHandler.ReadJsonWebToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (popTokenValidationPolicy.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await popTokenValidationPolicy.CnfDecryptionKeysResolverAsync(jsonWebToken, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = popTokenValidationPolicy.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new TokenValidationParameters()
            {
                TokenDecryptionKeys = decryptionKeys,
                RequireSignedTokens = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
            };

            JsonWebKey jsonWebKey;
            try
            {
                var decryptedJson = _jwtTokenHandler.DecryptToken(jsonWebToken, tokenDecryptionParameters);
                jsonWebKey = new JsonWebKey(decryptedJson);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23018, string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null")), e), e));
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return symmetricKey;
            else
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23019, jsonWebKey.GetType().ToString())));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            var popKeys = await GetPopKeysFromJkuAsync(jku, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);
            var popKeyCount = popKeys.Count;

            if (popKeyCount == 0)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else if (popKeyCount > 1)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else
                return popKeys[0];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="kid"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, string kid, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            var popKeys = await GetPopKeysFromJkuAsync(jku, popTokenValidationPolicy, cancellationToken).ConfigureAwait(false);

            foreach (var key in popKeys)
            {
                if (string.Equals(key.KeyId, kid.ToString(), StringComparison.Ordinal))
                    return key;
            }

            throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23021, kid, string.Join(", ", popKeys.Select(x => x.KeyId ?? "Null")))));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jkuSetUrl"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<IList<SecurityKey>> GetPopKeysFromJkuAsync(string jkuSetUrl, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jkuSetUrl))
                throw LogHelper.LogArgumentNullException(nameof(jkuSetUrl));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (!Utility.IsHttps(jkuSetUrl) && popTokenValidationPolicy.RequireHttpsForJkuResourceRetrieval)
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23006, jkuSetUrl)));

            try
            {
                var httpClient = popTokenValidationPolicy.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;
                var response = await httpClient.GetAsync(jkuSetUrl, cancellationToken).ConfigureAwait(false);
                var jsonWebKey = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
                return jsonWebKeySet.GetSigningKeys();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23022, jkuSetUrl, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="validatedAccessToken"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, JsonWebToken validatedAccessToken, HttpRequestPopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            if (popTokenValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popTokenValidationPolicy));

            if (popTokenValidationPolicy.PopKeyResolverFromKeyIdentifierAsync != null)
                return await popTokenValidationPolicy.PopKeyResolverFromKeyIdentifierAsync(kid, validatedAccessToken, cancellationToken).ConfigureAwait(false);
            else
            {
                throw LogHelper.LogExceptionMessage(new HttpRequestPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23023)));
            }
        }
        #endregion

        #region Private utility methods
        private string CalculateBase64UrlEncodedHash(string data)
        {
            return CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes(data));
        }

        private string CalculateBase64UrlEncodedHash(byte[] bytes)
        {
            using (var hash = SHA256.Create())
            {
                var hashedBytes = hash.ComputeHash(bytes);
                return Base64UrlEncoder.Encode(hashedBytes);
            }
        }

        private Dictionary<string, string> SanitizeQueryParams(Uri httpRequestUri)
        {
            // Remove repeated query params. https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var queryString = httpRequestUri.Query.TrimStart('?');
            var sanitizedQueryParams = new Dictionary<string, string>(StringComparer.Ordinal);

            if (string.IsNullOrEmpty(queryString))
                return sanitizedQueryParams;

            var queryParams = queryString.Split('&').Select(x => x.Split('=')).Select(x => new KeyValuePair<string, string>(x[0], x[1])).ToList();
            var repeatedQueryParams = new List<string>();
            foreach (var queryParam in queryParams)
            {
                var queryParamName = queryParam.Key;

                // if sanitizedQueryParams already contain the query parameter name it means that the query parameter name is repeated.
                // in that case query parameter name should not be added, and the existing entry in sanitizedQueryParams should be removed.
                if (sanitizedQueryParams.ContainsKey(queryParamName))
                {
                    sanitizedQueryParams.Remove(queryParamName);
                    repeatedQueryParams.Add(queryParamName);
                }
                else
                {
                    sanitizedQueryParams.Add(queryParamName, queryParam.Value);
                }
            }
            if (repeatedQueryParams.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23004, string.Join(", ", repeatedQueryParams)));
            }

            return sanitizedQueryParams;
        }

        private IDictionary<string, string> SanitizeHeaders(IDictionary<string, IEnumerable<string>> headers)
        {
            // Remove repeated headers. https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var sanitizedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var repeatedHeaders = new List<string>();
            foreach (var header in headers)
            {
                var headerName = header.Key;

                // Don't include the authorization header (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1).
                if (string.Equals(headerName, PopConstants.AuthorizationHeader, StringComparison.OrdinalIgnoreCase))
                    continue;

                // if sanitizedHeaders already contain the header name it means that the headerName is repeated.
                // in that case headerName should not be added, and the existing entry in sanitizedHeaders should be removed.
                if (sanitizedHeaders.ContainsKey(headerName))
                {
                    sanitizedHeaders.Remove(headerName);
                    repeatedHeaders.Add(headerName.ToLowerInvariant());
                }
                // if header has more than one value don't add it to the sanitizedHeaders as it's repeated.
                else if (header.Value.Count() > 1)
                {
                    repeatedHeaders.Add(headerName.ToLowerInvariant());
                }
                else
                    sanitizedHeaders.Add(headerName, header.Value.First());
            }

            if (repeatedHeaders.Any())
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23005, string.Join(", ", repeatedHeaders)));

            return sanitizedHeaders;
        }
        #endregion
    }
}
