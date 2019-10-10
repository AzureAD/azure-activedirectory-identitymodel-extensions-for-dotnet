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
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Serialization;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>
    /// A class which contains useful methods related to processing of SignedHttpRequest protocol.
    /// </summary>
    public static class SignedHttpRequestUtilities
    {
        /// <summary>
        /// Creates a "jwk" claim from a JsonWebKey representation of an asymmetric public key.
        /// </summary>
        /// <param name="jsonWebKey">JsonWebKey representation of an asymmetric public key.</param>
        /// <returns>A "jwk" claim as a JSON string.</returns>
        /// <remarks>https://tools.ietf.org/html/rfc7800#section-3.2</remarks>
        public static string CreateJwkClaim(JsonWebKey jsonWebKey)
        {
            if (jsonWebKey == null)
                throw LogHelper.LogArgumentNullException(nameof(jsonWebKey));

            if (string.IsNullOrEmpty(jsonWebKey.Kid))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX23033, nameof(jsonWebKey.Kid)), nameof(jsonWebKey.Kid)));

            if (!string.Equals(jsonWebKey.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal) &&
                !string.Equals(jsonWebKey.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX23034, nameof(jsonWebKey.Kty), string.Join(", ", JsonWebAlgorithmsKeyTypes.EllipticCurve, JsonWebAlgorithmsKeyTypes.RSA), nameof(jsonWebKey.Kty))));

            // exclude private parameters by using the JsonWebKeyIgnorePrivatePropertiesContractResolver,
            // that ignores private key properties during serialization into a JSON string.
            var jsonSerializerSettings = new JsonSerializerSettings()
            {
                ContractResolver = new JsonWebKeyIgnorePrivatePropertiesContractResolver(),
            };

            var jwk = JsonConvert.SerializeObject(jsonWebKey, jsonSerializerSettings);
            return $@"{{""{ConfirmationClaimTypes.Jwk}"":{jwk}}}";
        }

        /// <summary>
        /// Represents a contract resolver that ignores private/secret properties during serialization of a JWK into a JSON string.
        /// </summary>
        class JsonWebKeyIgnorePrivatePropertiesContractResolver : DefaultContractResolver
        {
            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                JsonProperty property = base.CreateProperty(member, memberSerialization);
                if (member.Name == nameof(JsonWebKey.D) ||   // ec or rsa
                    member.Name == nameof(JsonWebKey.DP) ||  // rsa
                    member.Name == nameof(JsonWebKey.DQ) ||  // rsa
                    member.Name == nameof(JsonWebKey.Oth) || // rsa
                    member.Name == nameof(JsonWebKey.P) ||   // rsa
                    member.Name == nameof(JsonWebKey.Q) ||   // rsa
                    member.Name == nameof(JsonWebKey.QI))    // rsa
                {
                    property.Ignored = true;
                }
                return property;
            }
        }

        /// <summary>
        /// Creates an authorization header using the SignedHttpRequest.
        /// </summary>
        /// <param name="signedHttpRequest">A signed http request.</param>
        /// <returns>A SignedHttpRequest value prefixed with the word "PoP".</returns>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1</remarks>
        public static string CreateSignedHttpRequestHeader(string signedHttpRequest)
        {
            if (string.IsNullOrEmpty(signedHttpRequest))
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            return $"{SignedHttpRequestConstants.AuthorizationHeaderSchemeName} {signedHttpRequest}";
        }

        /// <summary>
        /// A helper method that converts <see cref="HttpRequestMessage"/> into <see cref="HttpRequestData"/> object.
        /// </summary>
        /// <param name="httpRequestMessage"><see cref="HttpRequestMessage"/> object that represents incoming or outgoing http request.</param>
        /// <returns><see cref="HttpRequestData"/> object</returns>
        public static async Task<HttpRequestData> ToHttpRequestDataAsync(this HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestMessage));

            var httpRequestData = new HttpRequestData()
            {
                Method = httpRequestMessage.Method?.ToString(),
                Uri = httpRequestMessage.RequestUri
            };

            httpRequestData.AppendHeaders(httpRequestMessage.Headers);

            if (httpRequestMessage.Content != null)
            {
                httpRequestData.Body = await httpRequestMessage.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                httpRequestData.AppendHeaders(httpRequestMessage.Content.Headers);
            }

            return httpRequestData;
        }
    }
}
