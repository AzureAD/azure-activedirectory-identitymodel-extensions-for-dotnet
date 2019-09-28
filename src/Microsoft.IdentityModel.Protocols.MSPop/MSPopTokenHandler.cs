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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using ClaimTypes = Microsoft.IdentityModel.Protocols.MSPop.MSPopConstants.ClaimTypes;

namespace Microsoft.IdentityModel.Protocols.MSPop
{
    /// <summary>
    /// A handler designed for creating and validating MSPop tokens. 
    /// </summary>
    /// <remarks>The handler implementation is based on 'A Method for Signing HTTP Requests for OAuth' specification.</remarks>
    public class MSPopTokenHandler : IMSPopTokenCreator, IMSPopTokenValidator
    {
        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
        // "Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character."
        private readonly string _newlineSeparator = "\n";

        private readonly JsonWebTokenHandler _jwtTokenHandler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();

        #region MSPop token creation
        /// <summary>
        /// Creates an MSPop token using the <paramref name="msPopTokenCreationData"/>.
        /// /// </summary>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>An MSPop token as a JWS in Compact Serialization Format.</returns>
        public async Task<string> CreateMSPopTokenAsync(MSPopTokenCreationData msPopTokenCreationData, CancellationToken cancellationToken)
        {
            if (msPopTokenCreationData == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData));

            var header = CreateMSPopTokenHeader(msPopTokenCreationData);
            var payload = CreateMSPopTokenPayload(msPopTokenCreationData);
            return await SignMSPopTokenAsync(header, payload, msPopTokenCreationData, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates an MSPop token header.
        /// </summary>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <returns>An MSPop token header.</returns>
        protected virtual string CreateMSPopTokenHeader(MSPopTokenCreationData msPopTokenCreationData)
        {
            if (string.IsNullOrEmpty(msPopTokenCreationData.MSPopTokenSigningCredentials.Algorithm))
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.MSPopTokenSigningCredentials.Algorithm));

            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, msPopTokenCreationData.MSPopTokenSigningCredentials.Algorithm },
                { JwtHeaderParameterNames.Typ, MSPopConstants.TokenType }
            };

            if (msPopTokenCreationData.MSPopTokenSigningCredentials.Key?.KeyId != null)
                header.Add(JwtHeaderParameterNames.Kid, msPopTokenCreationData.MSPopTokenSigningCredentials.Key.KeyId);

            if (msPopTokenCreationData.MSPopTokenSigningCredentials.Key is X509SecurityKey x509SecurityKey)
                header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;

            return header.ToString(Formatting.None);
        }

        /// <summary>
        /// Creates an MSPop token payload.
        /// </summary>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <returns>An MSPop token payload.</returns>
        /// <remarks>
        /// Users can utilize <see cref="MSPopTokenCreationPolicy.AdditionalClaimCreator"/> to create additional claim(s) and add them to the MSPop token.
        /// </remarks>
        private protected virtual string CreateMSPopTokenPayload(MSPopTokenCreationData msPopTokenCreationData)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>();

            AddAtClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateTs)
                AddTsClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateM)
                AddMClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateU)
                AddUClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateP)
                AddPClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateQ)
                AddQClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateH)
                AddHClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateB)
                AddBClaim(payload, msPopTokenCreationData);

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CreateNonce)
                AddNonceClaim(payload, msPopTokenCreationData);

            msPopTokenCreationData.MSPopTokenCreationPolicy.AdditionalClaimCreator?.Invoke(payload, msPopTokenCreationData);

            return JObject.FromObject(payload).ToString(Formatting.None);
        }

        /// <summary>
        /// Encodes and signs an MSPop token(<paramref name="header"/>, <paramref name="payload"/>) using the <see cref="MSPopTokenCreationData.MSPopTokenSigningCredentials"/>.
        /// </summary>
        /// <param name="header">An MSPop token header.</param>
        /// <param name="payload">An MSPop token payload.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>MSPop token as a JWS in Compact Serialization Format.</returns>
        protected virtual Task<string> SignMSPopTokenAsync(string header, string payload, MSPopTokenCreationData msPopTokenCreationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var message = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))}";
            var signature = JwtTokenUtilities.CreateEncodedSignature(message, msPopTokenCreationData.MSPopTokenSigningCredentials);
            return Task.FromResult($"{message}.{signature}");
        }

        /// <summary>
        /// Adds the 'at' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        protected virtual void AddAtClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            payload.Add(ClaimTypes.At, msPopTokenCreationData.AccessToken);
        }

        /// <summary>
        /// Adds the 'ts' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void AddTsClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var msPopCreationTime = DateTime.UtcNow.Add(msPopTokenCreationData.MSPopTokenCreationPolicy.TimeAdjustment);
            payload.Add(ClaimTypes.Ts, (long)(msPopCreationTime - EpochTime.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// Adds the 'm' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateM"/> is set to <c>true</c>.
        /// </remarks>   
        protected virtual void AddMClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpMethod = msPopTokenCreationData.HttpRequestData.Method;

            if (string.IsNullOrEmpty(httpMethod))
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Method));

            if (!httpMethod.ToUpper().Equals(httpMethod, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

            payload.Add(ClaimTypes.M, httpMethod);
        }

        /// <summary>
        /// Adds the 'u' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateU"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddUClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = msPopTokenCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
            // u claim: The HTTP URL host component as a JSON string. This MAY include the port separated from the host by a colon in host:port format.
            // Including the port if it not the default port for the httpRequestUri scheme.
            var httpUrlHostComponent = httpRequestUri.Host;
            if (!httpRequestUri.IsDefaultPort)
                httpUrlHostComponent = $"{httpUrlHostComponent}:{httpRequestUri.Port}";

            payload.Add(ClaimTypes.U, httpUrlHostComponent);
        }

        /// <summary>
        /// Adds the 'm' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateP"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddPClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = msPopTokenCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);

            payload.Add(ClaimTypes.P, httpRequestUri.AbsolutePath);
        }

        /// <summary>
        /// Adds the 'q' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateQ"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddQClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = msPopTokenCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
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
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.Q, e), e));
            }
        }

        /// <summary>
        /// Adds the 'h' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateH"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddHClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestHeaders = msPopTokenCreationData.HttpRequestData.Headers;

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Headers));

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
                        stringBuffer.Append(encodedValue + _newlineSeparator);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(ClaimTypes.H, new List<object>() { headerNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.H, e), e));
            }
        }

        /// <summary>
        /// Adds the 'b' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateB"/> is set to <c>true</c>.
        /// </remarks> 
        protected virtual void AddBClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestBody = msPopTokenCreationData.HttpRequestData.Body;

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenCreationData.HttpRequestData.Body));

            try
            {
                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
                payload.Add(ClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }
        }

        /// <summary>
        /// Adds the 'nonce' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">MSPop token payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="msPopTokenCreationData">A structure that wraps parameters needed for MSPop token creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenCreationPolicy.CreateNonce"/> is set to <c>true</c>.
        /// Users can utilize <see cref="MSPopTokenCreationPolicy.CustomNonceCreator"/> to override the default behavior.
        /// </remarks>
        protected virtual void AddNonceClaim(Dictionary<string, object> payload, MSPopTokenCreationData msPopTokenCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (msPopTokenCreationData.MSPopTokenCreationPolicy.CustomNonceCreator != null)
                msPopTokenCreationData.MSPopTokenCreationPolicy.CustomNonceCreator(payload, msPopTokenCreationData);
            else
                payload.Add(ClaimTypes.Nonce, Guid.NewGuid().ToString("N"));
        }
        #endregion

        #region MSPop token validation
        /// <summary>
        /// Validates an MSPop token using the <paramref name="msPopTokenValidationData"/>.
        /// </summary>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<MSPopTokenValidationResult> ValidateMSPopTokenAsync(MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (msPopTokenValidationData == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenValidationData));

            var msPopToken = ReadAsSecurityToken(msPopTokenValidationData.MSPopToken);
            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            var accessToken = ReadAccessToken(jwtMSPopToken);
            var tokenValidationResult = await ValidateAccessTokenAsync(accessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            if (!tokenValidationResult.IsValid)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23013, tokenValidationResult.Exception), tokenValidationResult.Exception));

            // use the decrypted jwt if the accessToken is encrypted.
            if (tokenValidationResult.SecurityToken is JsonWebToken jwtValidatedAccessToken && jwtValidatedAccessToken.InnerToken != null)
                tokenValidationResult.SecurityToken = jwtValidatedAccessToken.InnerToken;

            var validatedMSPop = await ValidateMSPopAsync(jwtMSPopToken, tokenValidationResult.SecurityToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            return new MSPopTokenValidationResult()
            {
                AccessToken = accessToken,
                ClaimsIdentity = tokenValidationResult.ClaimsIdentity,
                ValidatedAccessToken = tokenValidationResult.SecurityToken,
                MSPopToken = jwtMSPopToken.EncodedToken,
                ValidatedMSPopToken = validatedMSPop
            };
        }

        /// <summary>
        /// Parses MSPop token into a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="msPopToken">MSPop token as a JWS in Compact Serialization Format.</param>
        /// <returns>An MSPop token as a <see cref="SecurityToken"/>.</returns>
        protected virtual SecurityToken ReadAsSecurityToken(string msPopToken)
        {
            return _jwtTokenHandler.ReadJsonWebToken(msPopToken);
        }

        /// <summary>
        /// Gets the value of the "at" claim.
        /// </summary>
        /// <param name="msPopToken">An MSPop token./>.</param>
        /// <returns>Access tokens as a JWT.</returns>
        protected virtual string ReadAccessToken(SecurityToken msPopToken)
        {
            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.At, out string accessToken) || accessToken == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.At)));

            return accessToken;
        }

        /// <summary>
        /// Validates an access token ("at").
        /// </summary>
        /// <param name="accessToken">An access token ("at") as a JWT.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A <see cref="TokenValidationResult"/>.</returns>
        protected virtual Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            var tokenValidationResult = _jwtTokenHandler.ValidateToken(accessToken, msPopTokenValidationData.AccessTokenValidationParameters);
            return Task.FromResult(tokenValidationResult);
        }

        /// <summary>
        /// Validates the MSPop token.
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during MSPop token validation process.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>Validated MSPop token.</returns>
        /// <remarks>
        /// The library doesn't provide any caching logic for replay validation purposes.
        /// <see cref="MSPopTokenValidationPolicy.MSPopTokenReplayValidatorAsync"/> delegate can be utilized for replay validation.
        /// Users can utilize <see cref="MSPopTokenValidationPolicy.AdditionalClaimValidatorAsync"/> to validate additional MSPop token claim(s).
        /// </remarks>
        private protected virtual async Task<SecurityToken> ValidateMSPopAsync(SecurityToken msPopToken, SecurityToken validatedAccessToken, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopTokenReplayValidatorAsync != null)
            {
                if (msPopToken is JsonWebToken jwtMSPopToken && jwtMSPopToken.TryGetPayloadValue(ClaimTypes.Nonce, out string nonce))
                    await msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopTokenReplayValidatorAsync(nonce, msPopToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
                else
                    await msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopTokenReplayValidatorAsync(string.Empty, msPopToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            }

            await ValidateMSPopSignatureAsync(msPopToken, validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateTs)
                ValidateTsClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateM)
                ValidateMClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateU)
                ValidateUClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateP)
                ValidatePClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateQ)
                ValidateQClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateH)
                ValidateHClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.ValidateB)
                ValidateBClaim(msPopToken, msPopTokenValidationData);

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.AdditionalClaimValidatorAsync != null)
                await msPopTokenValidationData.MSPopTokenValidationPolicy.AdditionalClaimValidatorAsync(msPopToken, validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            return msPopToken;
        }

        /// <summary>
        /// Resolves the PoP key and uses the key to validate the signature of the MSPop token.
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the MSPop validation process.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        protected virtual async Task ValidateMSPopSignatureAsync(SecurityToken msPopToken, SecurityToken validatedAccessToken, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            var popKey = await ResolvePopKeyAsync(validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            if (popKey == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23030)));

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopTokenSignatureValidatorAsync != null)
            {
                await msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopTokenSignatureValidatorAsync(popKey, msPopToken, validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            var signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, jwtMSPopToken.Alg);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23000, popKey?.ToString() ?? "Null", jwtMSPopToken.Alg ?? "Null")));

            try
            {
                var encodedBytes = Encoding.UTF8.GetBytes(jwtMSPopToken.EncodedHeader + "." + jwtMSPopToken.EncodedPayload);
                var signature = Base64UrlEncoder.DecodeBytes(jwtMSPopToken.EncodedSignature);

                if (!signatureProvider.Verify(encodedBytes, signature))
                    throw LogHelper.LogExceptionMessage(new MSPopInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009)));
            }
            finally
            {
                popKey.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Validates the MSPop token lifetime ("ts").
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void ValidateTsClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.Ts, out long tsClaimValue))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Ts)));

            DateTime utcNow = DateTime.UtcNow;
            DateTime msPopCreationTime = EpochTime.DateTime(tsClaimValue);
            DateTime msPopExpirationTime = msPopCreationTime.Add(msPopTokenValidationData.MSPopTokenValidationPolicy.MSPopLifetime);

            if (utcNow > msPopExpirationTime)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23010, utcNow, msPopExpirationTime)));
        }

        /// <summary>
        /// Validates the MSPop token "m" claim.
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateM"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateMClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var expectedHttpMethod = msPopTokenValidationData.HttpRequestData.Method;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (string.IsNullOrEmpty(expectedHttpMethod))
                throw LogHelper.LogArgumentNullException(nameof(expectedHttpMethod));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.M, out string httpMethod) || httpMethod == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.M)));

            // "get " is functionally the same as "GET".
            // different implementations might use differently formatted http verbs and we shouldn't fault.
            httpMethod = httpMethod.Trim();
            expectedHttpMethod = expectedHttpMethod.Trim();
            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.M, expectedHttpMethod, httpMethod)));
        }

        /// <summary>
        /// Validates the MSPop token "u" claim. 
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateU"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateUClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var httpRequestUri = msPopTokenValidationData.HttpRequestData.Uri;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenValidationData.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.U, out string uClaimValue) || uClaimValue == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.U)));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2
            // u: The HTTP URL host component as a JSON string.
            // This MAY include the port separated from the host by a colon in host:port format.
            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, ClaimTypes.U, expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue)));
        }

        /// <summary>
        /// Validates the MSPop token "p" claim. 
        /// </summary>
        /// <param name="msPopToken">MSPop token as a <see cref="JsonWebToken"/>.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateP"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidatePClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var httpRequestUri = msPopTokenValidationData.HttpRequestData.Uri;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopTokenValidationData.HttpRequestData.Uri));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.P, out string pClaimValue) || pClaimValue == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.P)));

            var expectedPClaimValue = httpRequestUri.AbsolutePath.TrimEnd('/');
            var expectedPClaimValueWithTrailingForwardSlash = expectedPClaimValue + '/';

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedPClaimValueWithTrailingForwardSlash, pClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, ClaimTypes.P, expectedPClaimValue, expectedPClaimValueWithTrailingForwardSlash, pClaimValue)));
        }

        /// <summary>
        /// Validates the MSPop token "q" claim. 
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateQ"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateQClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var httpRequestUri = msPopTokenValidationData.HttpRequestData.Uri;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.Q, out JArray qClaim) || qClaim == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Q)));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
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
                throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.Q, qClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastQueryParam = qClaimQueryParamNames.LastOrDefault();
                foreach (var queryParamName in qClaimQueryParamNames)
                {
                    if (!sanitizedQueryParams.TryGetValue(queryParamName, out var queryParamsValue))
                    {
                        throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23028, queryParamName, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));
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
                throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.Q, e), e));
            }

            if (!msPopTokenValidationData.MSPopTokenValidationPolicy.AcceptUncoveredQueryParameters && sanitizedQueryParams.Any())
                throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23029, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.Q, expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the MSPop token "h" claim. 
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateH"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateHClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var httpRequestHeaders = msPopTokenValidationData.HttpRequestData.Headers;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.H, out JArray hClaim) || hClaim == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.H)));

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
                throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.H, hClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastHeader = hClaimHeaderNames.Last();
                foreach (var headerName in hClaimHeaderNames)
                {
                    if (!sanitizedHeaders.TryGetValue(headerName, out var headerValue))
                    {
                        throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23027, headerName, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));
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
                throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.H, e), e));
            }

            if (!msPopTokenValidationData.MSPopTokenValidationPolicy.AcceptUncoveredHeaders && sanitizedHeaders.Any())
                throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23026, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.H, expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the MSPop token "b" claim. 
        /// </summary>
        /// <param name="msPopToken">An MSPop token.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="MSPopTokenValidationPolicy.ValidateB"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateBClaim(SecurityToken msPopToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            var httpRequestBody = msPopTokenValidationData.HttpRequestData.Body;

            if (msPopToken == null)
                throw LogHelper.LogArgumentNullException(nameof(msPopToken));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            if (!(msPopToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, msPopToken.GetType(), typeof(JsonWebToken), msPopToken)));

            if (!jwtMSPopToken.TryGetPayloadValue(ClaimTypes.B, out string bClaim) || bClaim == null)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.B)));

            string expectedBase64UrlEncodedHash;
            try
            {
                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }

            if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new MSPopInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.B, expectedBase64UrlEncodedHash, bClaim)));
        }
        #endregion

        #region Resolving PoP key
        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the 'cnf' claim.
        /// </summary>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during MSPop token validation process.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyAsync(SecurityToken validatedAccessToken, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (msPopTokenValidationData.MSPopTokenValidationPolicy.PopKeyResolverAsync != null)
                return await msPopTokenValidationData.MSPopTokenValidationPolicy.PopKeyResolverAsync(validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            var cnf = JObject.Parse(GetCnfClaimValue(validatedAccessToken, msPopTokenValidationData));
            if (cnf.TryGetValue(JwtHeaderParameterNames.Jwk, StringComparison.Ordinal, out var jwk))
            {
                return ResolvePopKeyFromJwk(jwk.ToString(), msPopTokenValidationData);
            }
            else if (cnf.TryGetValue(ClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
            {
                return await ResolvePopKeyFromJweAsync(jwe.ToString(), msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Jku, StringComparison.Ordinal, out var jku))
            {
                if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), kid.ToString(), msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
                else
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
            {
                return await ResolvePopKeyFromKeyIdentifierAsync(kid.ToString(), validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            }
            else
                throw LogHelper.LogExceptionMessage(new MSPopInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23014, cnf.ToString())));
        }

        /// <summary>
        /// Gets the JSON representation of the 'cnf' claim.
        /// </summary>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during MSPop token validation process.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <returns>JSON representation of the 'cnf' claim.</returns>
        protected virtual string GetCnfClaimValue(SecurityToken validatedAccessToken, MSPopTokenValidationData msPopTokenValidationData)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (!(validatedAccessToken is JsonWebToken jwtValidatedAccessToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, validatedAccessToken.GetType(), typeof(JsonWebToken), validatedAccessToken)));

            if (jwtValidatedAccessToken.TryGetPayloadValue(ClaimTypes.Cnf, out JObject cnf) || cnf == null)
                return cnf.ToString();
            else
                throw LogHelper.LogExceptionMessage(new MSPopInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Cnf)));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the asymmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwk">An asymmetric representation of a PoP key (JSON).</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual SecurityKey ResolvePopKeyFromJwk(string jwk, MSPopTokenValidationData msPopTokenValidationData)
        {
            if (string.IsNullOrEmpty(jwk))
                throw LogHelper.LogArgumentNullException(nameof(jwk));

            var jsonWebKey = new JsonWebKey(jwk);

            if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out var key))
            {
                if (key is AsymmetricSecurityKey)
                    return key;
                else
                    throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23015, key.GetType().ToString())));
            }
            else
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23016, jsonWebKey.ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the encrypted symmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwe">An encrypted symmetric representation of a PoP key (JSON).</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            var jsonWebToken = ReadAsSecurityToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (msPopTokenValidationData.MSPopTokenValidationPolicy.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await msPopTokenValidationData.MSPopTokenValidationPolicy.CnfDecryptionKeysResolverAsync(jsonWebToken, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = msPopTokenValidationData.MSPopTokenValidationPolicy.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new TokenValidationParameters()
            {
                TokenDecryptionKeys = decryptionKeys,
                RequireSignedTokens = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
            };

            if (!(jsonWebToken is JsonWebToken jwtMSPopToken))
                throw LogHelper.LogExceptionMessage(new MSPopValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, jsonWebToken.GetType(), typeof(JsonWebToken), jsonWebToken)));

            JsonWebKey jsonWebKey;
            try
            {
                var decryptedJson = _jwtTokenHandler.DecryptToken(jwtMSPopToken, tokenDecryptionParameters);
                jsonWebKey = new JsonWebKey(decryptedJson);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23018, string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null")), e), e));
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return symmetricKey;
            else
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23019, jsonWebKey.GetType().ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP JWK set.
        /// The method throws an exception is there is more than one resolved PoP key.
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            var popKeys = await GetPopKeysFromJkuAsync(jkuSetUrl, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            var popKeyCount = popKeys.Count;

            if (popKeyCount == 0)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else if (popKeyCount > 1)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else
                return popKeys[0];
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP key.  
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="kid">A PoP key identifier.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, string kid, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            var popKeys = await GetPopKeysFromJkuAsync(jkuSetUrl, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);

            foreach (var key in popKeys)
            {
                if (string.Equals(key.KeyId, kid.ToString(), StringComparison.Ordinal))
                    return key;
            }

            throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23021, kid, string.Join(", ", popKeys.Select(x => x.KeyId ?? "Null")))));
        }

        /// <summary>
        /// Gets a JWK set of PoP <see cref="SecurityKey"/> from the <paramref name="jkuSetUrl"/>.
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A collection of PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<IList<SecurityKey>> GetPopKeysFromJkuAsync(string jkuSetUrl, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jkuSetUrl))
                throw LogHelper.LogArgumentNullException(nameof(jkuSetUrl));

            if (!Utility.IsHttps(jkuSetUrl) && msPopTokenValidationData.MSPopTokenValidationPolicy.RequireHttpsForJkuResourceRetrieval)
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23006, jkuSetUrl)));

            try
            {
                var httpClient = msPopTokenValidationData.MSPopTokenValidationPolicy.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;
                var response = await httpClient.GetAsync(jkuSetUrl, cancellationToken).ConfigureAwait(false);
                var jsonWebKey = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
                return jsonWebKeySet.GetSigningKeys();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23022, jkuSetUrl, e), e));
            }
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> using a key identifier of a PoP key. 
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during MSPop token validation process.</param>
        /// <param name="msPopTokenValidationData">A structure that wraps parameters needed for MSPop token validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        /// <remarks>
        /// To resolve a PoP <see cref="SecurityKey"/> using only the 'kid' claim, set the <see cref="MSPopTokenValidationPolicy.PopKeyResolverFromKeyIdAsync"/> delegate.
        /// </remarks>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, SecurityToken validatedAccessToken, MSPopTokenValidationData msPopTokenValidationData, CancellationToken cancellationToken)
        {
            if (msPopTokenValidationData.MSPopTokenValidationPolicy.PopKeyResolverFromKeyIdAsync != null)
                return await msPopTokenValidationData.MSPopTokenValidationPolicy.PopKeyResolverFromKeyIdAsync(kid, validatedAccessToken, msPopTokenValidationData, cancellationToken).ConfigureAwait(false);
            else
            {
                throw LogHelper.LogExceptionMessage(new MSPopInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23023)));
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

        /// <summary>
        /// Ensures that the <paramref name="uri"/> is <see cref="UriKind.Absolute"/>.
        /// If <paramref name="uri"/> is <see cref="UriKind.Absolute"/>, the method returns it as-is.
        /// If <paramref name="uri"/> is <see cref="UriKind.Relative"/>, new helper <see cref="UriKind.Absolute"/> URI is created and returned.
        /// Throws in case that an <see cref="UriKind.Absolute"/> URI can't be created.
        /// </summary>
        private Uri EnsureAbsoluteUri(Uri uri)
        {
            if (uri.IsAbsoluteUri)
            {
                return uri;
            }
            else
            {
                if (!Uri.TryCreate(_baseUriHelper, uri, out Uri absoluteUri))
                    throw LogHelper.LogExceptionMessage(new MSPopCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, uri.ToString())));

                return absoluteUri;
            }
        }

        /// <summary>
        /// Sanitizes the query params to comply with the specification.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.</remarks>
        private Dictionary<string, string> SanitizeQueryParams(Uri httpRequestUri)
        {
            // Remove repeated query params according to the spec: https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
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

                // if sanitizedQueryParams already contains the query parameter name it means that the query parameter name is repeated.
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

        /// <summary>
        /// Sanitizes the headers to comply with the specification.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5
        /// </remarks>
        private Dictionary<string, string> SanitizeHeaders(IDictionary<string, IEnumerable<string>> headers)
        {
            // Remove repeated headers according to the spec: https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var sanitizedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var repeatedHeaders = new List<string>();
            foreach (var header in headers)
            {
                var headerName = header.Key;

                // Don't include the authorization header (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1).
                if (string.Equals(headerName, MSPopConstants.AuthorizationHeader, StringComparison.OrdinalIgnoreCase))
                    continue;

                // if sanitizedHeaders already contains the header name it means that the headerName is repeated.
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
