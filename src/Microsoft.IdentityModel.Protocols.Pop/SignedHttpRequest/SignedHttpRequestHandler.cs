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
using System.Collections.Specialized;
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
using ClaimTypes = Microsoft.IdentityModel.Protocols.Pop.PopConstants.SignedHttpRequest.ClaimTypes;

namespace Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest
{
    /// <summary>
    /// A handler designed for creating and validating signed http requests. 
    /// </summary>
    /// <remarks>The handler implementation is based on 'A Method for Signing HTTP Requests for OAuth' specification.</remarks>
    public class SignedHttpRequestHandler : ISignedHttpRequestCreator, ISignedHttpRequestValidator
    {
        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
        // "Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character."
        private readonly string _newlineSeparator = "\n";

        private readonly JsonWebTokenHandler _jwtTokenHandler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();

        #region SignedHttpRequest creation
        /// <summary>
        /// Creates a signed http request using the <paramref name="signedHttpRequestCreationData"/>.
        /// /// </summary>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A signed http request as a JWS in Compact Serialization Format.</returns>
        public async Task<string> CreateSignedHttpRequestAsync(SignedHttpRequestCreationData signedHttpRequestCreationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestCreationData == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData));

            var header = CreateHttpRequestHeader(signedHttpRequestCreationData);
            var payload = CreateHttpRequestPayload(signedHttpRequestCreationData);
            return await SignHttpRequestAsync(header, payload, signedHttpRequestCreationData, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates a JSON representation of a HttpRequest header.
        /// </summary>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <returns>A JSON representation of an HttpRequest header.</returns>
        protected virtual string CreateHttpRequestHeader(SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, signedHttpRequestCreationData.SigningCredentials.Algorithm },
                { JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType }
            };

            if (signedHttpRequestCreationData.SigningCredentials.Key?.KeyId != null)
                header.Add(JwtHeaderParameterNames.Kid, signedHttpRequestCreationData.SigningCredentials.Key.KeyId);

            if (signedHttpRequestCreationData.SigningCredentials.Key is X509SecurityKey x509SecurityKey)
                header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;

            return header.ToString(Formatting.None);
        }

        /// <summary>
        /// Creates a JSON representation of a HttpRequest payload.
        /// </summary>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <returns>A JSON representation of an HttpRequest payload.</returns>
        /// <remarks>
        /// Users can utilize <see cref="SignedHttpRequestCreationPolicy.AdditionalClaimCreator"/> to create additional claim(s) and add them to the signed http request.
        /// </remarks>
        private protected virtual string CreateHttpRequestPayload(SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>();

            AddAtClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateTs)
                AddTsClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateM)
                AddMClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateU)
                AddUClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateP)
                AddPClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateQ)
                AddQClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateH)
                AddHClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateB)
                AddBClaim(payload, signedHttpRequestCreationData);

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CreateNonce)
                AddNonceClaim(payload, signedHttpRequestCreationData);

            signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.AdditionalClaimCreator?.Invoke(payload, signedHttpRequestCreationData);

            return ConvertToJson(payload);
        }

        /// <summary>
        /// Converts a dictionary representation of HttpRequest into a JSON string.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <returns>A JSON string.</returns>
        protected virtual string ConvertToJson(Dictionary<string, object> payload)
        {
            return JObject.FromObject(payload).ToString(Formatting.None);
        }

        /// <summary>
        /// Encodes and signs a http request message (<paramref name="header"/>, <paramref name="payload"/>) using the <see cref="SignedHttpRequestCreationData.SigningCredentials"/>.
        /// </summary>
        /// <param name="header">A JSON representation of an HttpRequest header.</param>
        /// <param name="payload">A JSON representation of an HttpRequest payload.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>SignedHttpRequest as a JWS in Compact Serialization Format.</returns>
        protected virtual Task<string> SignHttpRequestAsync(string header, string payload, SignedHttpRequestCreationData signedHttpRequestCreationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var message = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))}";
            var signature = JwtTokenUtilities.CreateEncodedSignature(message, signedHttpRequestCreationData.SigningCredentials);
            return Task.FromResult($"{message}.{signature}");
        }

        /// <summary>
        /// Adds the 'at' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        protected virtual void AddAtClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            payload.Add(ClaimTypes.At, signedHttpRequestCreationData.AccessToken);
        }

        /// <summary>
        /// Adds the 'ts' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void AddTsClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var signedHttpRequestCreationTime = DateTime.UtcNow.Add(signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.TimeAdjustment);
            payload.Add(ClaimTypes.Ts, (long)(signedHttpRequestCreationTime - EpochTime.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// Adds the 'm' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateM"/> is set to <c>true</c>.
        /// </remarks>   
        protected virtual void AddMClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpMethod = signedHttpRequestCreationData.HttpRequestData.Method;

            if (string.IsNullOrEmpty(httpMethod))
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData.HttpRequestData.Method));

            if (!httpMethod.ToUpper().Equals(httpMethod, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

            payload.Add(ClaimTypes.M, httpMethod);
        }

        /// <summary>
        /// Adds the 'u' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateU"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddUClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

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
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateP"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddPClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);

            payload.Add(ClaimTypes.P, httpRequestUri.AbsolutePath);
        }

        /// <summary>
        /// Adds the 'q' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateQ"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddQClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestCreationData.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> queryParamNameList = new List<string>();
            try
            {
                var lastQueryParam = sanitizedQueryParams.LastOrDefault();
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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.Q, e), e));
            }
        }

        /// <summary>
        /// Adds the 'h' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateH"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddHClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signedHttpRequestCreationData.HttpRequestData.Headers == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestCreationData.HttpRequestData.Headers));

            var sanitizedHeaders = SanitizeHeaders(signedHttpRequestCreationData.HttpRequestData.Headers);
            StringBuilder stringBuffer = new StringBuilder();
            List<string> headerNameList = new List<string>();
            try
            {
                var lastHeader = sanitizedHeaders.LastOrDefault();
                foreach (var header in sanitizedHeaders)
                {
                    var headerName = header.Key.ToLower();
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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.H, e), e));
            }
        }

        /// <summary>
        /// Adds the 'b' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateB"/> is set to <c>true</c>.
        /// </remarks> 
        protected virtual void AddBClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestBody = signedHttpRequestCreationData.HttpRequestData.Body;

            if (httpRequestBody == null)
                httpRequestBody = new byte[0];

            try
            {
                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
                payload.Add(ClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }
        }

        /// <summary>
        /// Adds the 'nonce' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestCreationData">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationPolicy.CreateNonce"/> is set to <c>true</c>.
        /// Users can utilize <see cref="SignedHttpRequestCreationPolicy.CustomNonceCreator"/> to override the default behavior.
        /// </remarks>
        protected virtual void AddNonceClaim(Dictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CustomNonceCreator != null)
                signedHttpRequestCreationData.SignedHttpRequestCreationPolicy.CustomNonceCreator(payload, signedHttpRequestCreationData);
            else
                payload.Add(ClaimTypes.Nonce, Guid.NewGuid().ToString("N"));
        }
        #endregion

        #region SignedHttpRequest validation
        /// <summary>
        /// Validates a signed http request using the <paramref name="signedHttpRequestValidationData"/>.
        /// </summary>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<SignedHttpRequestValidationResult> ValidateSignedHttpRequestAsync(SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationData));

            var signedHttpRequest = ReadAsSecurityToken(signedHttpRequestValidationData.SignedHttpRequest);
            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));
            var accessToken = ReadAccessToken(jwtSignedHttpRequest);
            var tokenValidationResult = await ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            if (!tokenValidationResult.IsValid)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23013, tokenValidationResult.Exception), tokenValidationResult.Exception));

            // use the decrypted jwt if the accessToken is encrypted.
            if (tokenValidationResult.SecurityToken is JsonWebToken jwtValidatedAccessToken && jwtValidatedAccessToken.InnerToken != null)
                tokenValidationResult.SecurityToken = jwtValidatedAccessToken.InnerToken;

            var validatedSignedHttpRequest = await ValidateSignedHttpRequestAsync(jwtSignedHttpRequest, tokenValidationResult.SecurityToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            return new SignedHttpRequestValidationResult()
            {
                AccessToken = accessToken,
                ClaimsIdentity = tokenValidationResult.ClaimsIdentity,
                ValidatedAccessToken = tokenValidationResult.SecurityToken,
                SignedHttpRequest = jwtSignedHttpRequest.EncodedToken,
                ValidatedSignedHttpRequest = validatedSignedHttpRequest
            };
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <returns>A <see cref="SecurityToken"/>.</returns>
        protected virtual SecurityToken ReadAsSecurityToken(string token)
        {
            return _jwtTokenHandler.ReadJsonWebToken(token);
        }

        /// <summary>
        /// Gets the value of the "at" claim.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <returns>Access tokens as a JWT.</returns>
        protected virtual string ReadAccessToken(SecurityToken signedHttpRequest)
        {
            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.At, out string accessToken) || accessToken == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.At)));

            return accessToken;
        }

        /// <summary>
        /// Validates an access token ("at").
        /// </summary>
        /// <param name="accessToken">An access token ("at") as a JWT.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A <see cref="TokenValidationResult"/>.</returns>
        protected virtual Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            var tokenValidationResult = _jwtTokenHandler.ValidateToken(accessToken, signedHttpRequestValidationData.AccessTokenValidationParameters);
            return Task.FromResult(tokenValidationResult);
        }

        /// <summary>
        /// Validates signed http request.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        /// <remarks>
        /// The library doesn't provide any caching logic for replay validation purposes.
        /// <see cref="SignedHttpRequestValidationPolicy.SignedHttpRequestReplayValidatorAsync"/> delegate can be utilized for replay validation.
        /// Users can utilize <see cref="SignedHttpRequestValidationPolicy.AdditionalClaimValidatorAsync"/> to validate additional signed http request claim(s).
        /// </remarks>
        private protected virtual async Task<SecurityToken> ValidateSignedHttpRequestAsync(SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestReplayValidatorAsync != null)
            {
                if (signedHttpRequest is JsonWebToken jwtSignedHttpRequest && jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.Nonce, out string nonce))
                    await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestReplayValidatorAsync(nonce, jwtSignedHttpRequest, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
                else
                    await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestReplayValidatorAsync(string.Empty, signedHttpRequest, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }

            await ValidateSignedHttpRequestSignatureAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateTs)
                ValidateTsClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateM)
                ValidateMClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateU)
                ValidateUClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateP)
                ValidatePClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateQ)
                ValidateQClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateH)
                ValidateHClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.ValidateB)
                ValidateBClaim(signedHttpRequest, signedHttpRequestValidationData);

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.AdditionalClaimValidatorAsync != null)
                await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.AdditionalClaimValidatorAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            return signedHttpRequest;
        }

        /// <summary>
        /// Resolves the PoP key and uses the key to validate the signature of the signed http request.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        protected virtual async Task ValidateSignedHttpRequestSignatureAsync(SecurityToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            var popKey = await ResolvePopKeyAsync(validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            if (popKey == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23030)));

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestSignatureValidatorAsync != null)
            {
                await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestSignatureValidatorAsync(popKey, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            var signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, jwtSignedHttpRequest.Alg);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23000, popKey?.ToString() ?? "Null", jwtSignedHttpRequest.Alg ?? "Null")));

            try
            {
                var encodedBytes = Encoding.UTF8.GetBytes(jwtSignedHttpRequest.EncodedHeader + "." + jwtSignedHttpRequest.EncodedPayload);
                var signature = Base64UrlEncoder.DecodeBytes(jwtSignedHttpRequest.EncodedSignature);

                if (!signatureProvider.Verify(encodedBytes, signature))
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009)));
            }
            finally
            {
                popKey.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Validates the signed http request lifetime ("ts").
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void ValidateTsClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.Ts, out long tsClaimValue))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Ts)));

            DateTime utcNow = DateTime.UtcNow;
            DateTime signedHttpRequestCreationTime = EpochTime.DateTime(tsClaimValue);
            DateTime signedHttpRequestExpirationTime = signedHttpRequestCreationTime.Add(signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.SignedHttpRequestLifetime);

            if (utcNow > signedHttpRequestExpirationTime)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23010, utcNow, signedHttpRequestExpirationTime)));
        }

        /// <summary>
        /// Validates the signed http request "m" claim.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateM"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateMClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var expectedHttpMethod = signedHttpRequestValidationData.HttpRequestData.Method;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (string.IsNullOrEmpty(expectedHttpMethod))
                throw LogHelper.LogArgumentNullException(nameof(expectedHttpMethod));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.M, out string httpMethod) || httpMethod == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.M)));

            // "get " is functionally the same as "GET".
            // different implementations might use differently formatted http verbs and we shouldn't fault.
            httpMethod = httpMethod.Trim();
            expectedHttpMethod = expectedHttpMethod.Trim();
            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.M, expectedHttpMethod, httpMethod)));
        }

        /// <summary>
        /// Validates the signed http request "u" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateU"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateUClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var httpRequestUri = signedHttpRequestValidationData.HttpRequestData.Uri;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationData.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.U, out string uClaimValue) || uClaimValue == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.U)));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2
            // u: The HTTP URL host component as a JSON string.
            // This MAY include the port separated from the host by a colon in host:port format.
            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, ClaimTypes.U, expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue)));
        }

        /// <summary>
        /// Validates the signed http request "p" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateP"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidatePClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var httpRequestUri = signedHttpRequestValidationData.HttpRequestData.Uri;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationData.HttpRequestData.Uri));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.P, out string pClaimValue) || pClaimValue == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.P)));

            var expectedPClaimValue = httpRequestUri.AbsolutePath.TrimEnd('/');
            var expectedPClaimValueWithTrailingForwardSlash = expectedPClaimValue + '/';

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedPClaimValueWithTrailingForwardSlash, pClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, ClaimTypes.P, expectedPClaimValue, expectedPClaimValueWithTrailingForwardSlash, pClaimValue)));
        }

        /// <summary>
        /// Validates the signed http request "q" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateQ"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateQClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var httpRequestUri = signedHttpRequestValidationData.HttpRequestData.Uri;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.Q, out JArray qClaim) || qClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Q)));

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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.Q, qClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastQueryParam = qClaimQueryParamNames.LastOrDefault();
                foreach (var queryParamName in qClaimQueryParamNames)
                {
                    if (!sanitizedQueryParams.TryGetValue(queryParamName, out var queryParamsValue))
                    {
                        throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23028, queryParamName, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));
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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.Q, e), e));
            }

            if (!signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.AcceptUncoveredQueryParameters && sanitizedQueryParams.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23029, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.Q, expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the signed http request "h" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateH"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateHClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var httpRequestHeaders = signedHttpRequestValidationData.HttpRequestData.Headers;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.H, out JArray hClaim) || hClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.H)));

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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, ClaimTypes.H, hClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastHeader = hClaimHeaderNames.Last();
                foreach (var headerName in hClaimHeaderNames)
                {
                    if (!sanitizedHeaders.TryGetValue(headerName, out var headerValue))
                    {
                        throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23027, headerName, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));
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
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, ClaimTypes.H, e), e));
            }

            if (!signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.AcceptUncoveredHeaders && sanitizedHeaders.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23026, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.H, expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the signed http request "b" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationPolicy.ValidateB"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateBClaim(SecurityToken signedHttpRequest, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            var httpRequestBody = signedHttpRequestValidationData.HttpRequestData.Body;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            if (!(signedHttpRequest is JsonWebToken jwtSignedHttpRequest))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, signedHttpRequest.GetType(), typeof(JsonWebToken), signedHttpRequest)));

            if (!jwtSignedHttpRequest.TryGetPayloadValue(ClaimTypes.B, out string bClaim) || bClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.B)));

            string expectedBase64UrlEncodedHash;
            try
            {
                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, ClaimTypes.B, e), e));
            }

            if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, ClaimTypes.B, expectedBase64UrlEncodedHash, bClaim)));
        }
        #endregion

        #region Resolving PoP key
        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the 'cnf' claim.
        /// </summary>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyAsync(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.PopKeyResolverAsync != null)
                return await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.PopKeyResolverAsync(validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            var cnf = JObject.Parse(GetCnfClaimValue(validatedAccessToken, signedHttpRequestValidationData));
            if (cnf.TryGetValue(JwtHeaderParameterNames.Jwk, StringComparison.Ordinal, out var jwk))
            {
                return ResolvePopKeyFromJwk(jwk.ToString(), signedHttpRequestValidationData);
            }
            else if (cnf.TryGetValue(ClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
            {
                return await ResolvePopKeyFromJweAsync(jwe.ToString(), signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Jku, StringComparison.Ordinal, out var jku))
            {
                if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), kid.ToString(), signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
                else
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
            {
                return await ResolvePopKeyFromKeyIdentifierAsync(kid.ToString(), validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            }
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23014, cnf.ToString())));
        }

        /// <summary>
        /// Gets the JSON representation of the 'cnf' claim.
        /// </summary>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <returns>JSON representation of the 'cnf' claim.</returns>
        protected virtual string GetCnfClaimValue(SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (!(validatedAccessToken is JsonWebToken jwtValidatedAccessToken))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, validatedAccessToken.GetType(), typeof(JsonWebToken), validatedAccessToken)));

            if (jwtValidatedAccessToken.TryGetPayloadValue(ClaimTypes.Cnf, out JObject cnf) || cnf == null)
                return cnf.ToString();
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ClaimTypes.Cnf)));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the asymmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwk">An asymmetric representation of a PoP key (JSON).</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual SecurityKey ResolvePopKeyFromJwk(string jwk, SignedHttpRequestValidationData signedHttpRequestValidationData)
        {
            if (string.IsNullOrEmpty(jwk))
                throw LogHelper.LogArgumentNullException(nameof(jwk));

            var jsonWebKey = new JsonWebKey(jwk);

            if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out var key))
            {
                if (key is AsymmetricSecurityKey)
                    return key;
                else
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23015, key.GetType().ToString())));
            }
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23016, jsonWebKey.ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the encrypted symmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwe">An encrypted symmetric representation of a PoP key (JSON).</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            var jsonWebToken = ReadAsSecurityToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.CnfDecryptionKeysResolverAsync(jsonWebToken, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new TokenValidationParameters()
            {
                TokenDecryptionKeys = decryptionKeys,
                RequireSignedTokens = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
            };

            if (!(jsonWebToken is JsonWebToken jwtCnf))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, jsonWebToken.GetType(), typeof(JsonWebToken), jsonWebToken)));

            JsonWebKey jsonWebKey;
            try
            {
                var decryptedJson = _jwtTokenHandler.DecryptToken(jwtCnf, tokenDecryptionParameters);
                jsonWebKey = new JsonWebKey(decryptedJson);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23018, string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null")), e), e));
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return symmetricKey;
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23019, jsonWebKey.GetType().ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP JWK set.
        /// The method throws an exception is there is more than one resolved PoP key.
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            var popKeys = await GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            var popKeyCount = popKeys.Count;

            if (popKeyCount == 0)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else if (popKeyCount > 1)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else
                return popKeys[0];
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP key.  
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="kid">A PoP key identifier.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, string kid, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            var popKeys = await GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);

            foreach (var key in popKeys)
            {
                if (string.Equals(key.KeyId, kid.ToString(), StringComparison.Ordinal))
                    return key;
            }

            throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23021, kid, string.Join(", ", popKeys.Select(x => x.KeyId ?? "Null")))));
        }

        /// <summary>
        /// Gets a JWK set of PoP <see cref="SecurityKey"/> from the <paramref name="jkuSetUrl"/>.
        /// </summary>
        /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A collection of PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<IList<SecurityKey>> GetPopKeysFromJkuAsync(string jkuSetUrl, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jkuSetUrl))
                throw LogHelper.LogArgumentNullException(nameof(jkuSetUrl));

            if (!Utility.IsHttps(jkuSetUrl) && signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.RequireHttpsForJkuResourceRetrieval)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23006, jkuSetUrl)));

            try
            {
                var httpClient = signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;
                var response = await httpClient.GetAsync(jkuSetUrl, cancellationToken).ConfigureAwait(false);
                var jsonWebKey = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
                return jsonWebKeySet.GetSigningKeys();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23022, jkuSetUrl, e), e));
            }
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> using a key identifier of a PoP key. 
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationData">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        /// <remarks>
        /// To resolve a PoP <see cref="SecurityKey"/> using only the 'kid' claim, set the <see cref="SignedHttpRequestValidationPolicy.PopKeyResolverFromKeyIdAsync"/> delegate.
        /// </remarks>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationData signedHttpRequestValidationData, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.PopKeyResolverFromKeyIdAsync != null)
                return await signedHttpRequestValidationData.SignedHttpRequestValidationPolicy.PopKeyResolverFromKeyIdAsync(kid, validatedAccessToken, signedHttpRequestValidationData, cancellationToken).ConfigureAwait(false);
            else
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23023)));
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
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, uri.ToString())));

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
            var sanitizedQueryParams = new Dictionary<string, string>(StringComparer.Ordinal);
            var repeatedQueryParams = new List<string>();

            var queryString = httpRequestUri.Query.TrimStart('?');
            if (string.IsNullOrEmpty(queryString))
                return sanitizedQueryParams;

            var queryParamKeyValuePairs = queryString.Split('&');
            foreach (var queryParamValuePair in queryParamKeyValuePairs)
            {
                var queryParamKeyValuePairArray = queryParamValuePair.Split('=');
                if (queryParamKeyValuePairArray.Count() == 2)
                {
                    var queryParamName = queryParamKeyValuePairArray[0];
                    var queryParamValue = queryParamKeyValuePairArray[1];
                    if (!string.IsNullOrEmpty(queryParamName))
                    {
                        // if sanitizedQueryParams already contains the query parameter name it means that the queryParamName is repeated.
                        // in that case queryParamName should not be added, and the existing entry in sanitizedQueryParams should be removed.
                        if (sanitizedQueryParams.ContainsKey(queryParamName))
                            repeatedQueryParams.Add(queryParamName);
                        else if (!string.IsNullOrEmpty(queryParamValue))
                            sanitizedQueryParams.Add(queryParamName, queryParamValue);
                    }
                }
            }

            if (repeatedQueryParams.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23004, string.Join(", ", repeatedQueryParams)));

                foreach (var repeatedQueryParam in repeatedQueryParams)
                {
                    if (sanitizedQueryParams.ContainsKey(repeatedQueryParam))
                    sanitizedQueryParams.Remove(repeatedQueryParam);
                }
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

                if (string.IsNullOrEmpty(headerName))
                    continue;

                // Don't include the authorization header (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1).
                if (string.Equals(headerName, PopConstants.AuthorizationHeader, StringComparison.OrdinalIgnoreCase))
                    continue;

                // if sanitizedHeaders already contains the header name it means that the headerName is repeated.
                // in that case headerName should not be added, and the existing entry in sanitizedHeaders should be removed.
                if (sanitizedHeaders.ContainsKey(headerName))
                {
                    repeatedHeaders.Add(headerName.ToLower());
                }
                // if header has more than one value don't add it to the sanitizedHeaders as it's repeated.
                else if (header.Value.Count() > 1)
                {
                    repeatedHeaders.Add(headerName.ToLower());
                }
                else if (header.Value.Count() == 1 && !string.IsNullOrEmpty(header.Value.First()))
                    sanitizedHeaders.Add(headerName, header.Value.First());
            }

            if (repeatedHeaders.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23005, string.Join(", ", repeatedHeaders)));

                foreach (var repeatedHeaderName in repeatedHeaders)
                {
                    if (sanitizedHeaders.ContainsKey(repeatedHeaderName))
                        sanitizedHeaders.Remove(repeatedHeaderName);
                }
            }

            return sanitizedHeaders;
        }
        #endregion
    }
}
