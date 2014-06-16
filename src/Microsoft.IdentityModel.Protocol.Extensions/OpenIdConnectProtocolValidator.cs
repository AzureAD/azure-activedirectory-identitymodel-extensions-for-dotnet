//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// OpenIdConnectProtocolValidator - TODO
    /// </summary>
    public static class OpenIdConnectProtocolValidator
    {
        private static List<string> requiredClaims = new List<string> { JwtRegisteredClaimNames.Aud, JwtRegisteredClaimNames.Exp, JwtRegisteredClaimNames.Iat, JwtRegisteredClaimNames.Iss, JwtRegisteredClaimNames.Sub };

        /// <summary>
        /// Generates a value suitable to use as a nonce.
        /// </summary>
        /// <returns></returns>
        public static string GenerateNonce() 
        { 
            return Guid.NewGuid().ToString() + Guid.NewGuid().ToString(); 
        }

        /// <summary>
        /// Validates that a <see cref="JwtSecurityToken"/> is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="jwt">the <see cref="JwtSecurityToken"/>to validate.</param>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> to use for validating.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the <see cref="JwtSecurityToken"/> is missing any required claims as per: http://openid.net/specs/openid-connect-core-1_0.html#IDToken </exception>
        /// <remarks><see cref="OpenIdConnectProtocolValidationParameters.Nonce"/> and <see cref="OpenIdConnectProtocolValidationParameters.AuthorizationCode"/> will be validated if they are not 'null' or 'whitespace'.</remarks>
        public static void Validate(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext)
        {
            if (jwt == null)
                throw new ArgumentNullException("jwt");

            if (validationContext == null)
                throw new ArgumentNullException("validationContext");

            // required claims
            if (jwt.Payload.Aud.Count == 0)
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Aud.ToLowerInvariant(), jwt));

            if (!jwt.Payload.Exp.HasValue)
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Exp.ToLowerInvariant(), jwt));

            if (!jwt.Payload.Iat.HasValue)
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Iat.ToLowerInvariant(), jwt));

            if (jwt.Payload.Iss == null)
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Iss.ToLowerInvariant(), jwt));

            if (jwt.Payload.Sub == null)
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Sub.ToLowerInvariant(), jwt));

            OpenIdConnectProtocolValidationParameters validationParameters = validationContext.OpenIdConnectProtocolValidationParameters;

            // optional claims
            if (validationParameters.RequireAcr && string.IsNullOrWhiteSpace(jwt.Payload.Acr))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10312, jwt));

            if (validationParameters.RequireAmr && string.IsNullOrWhiteSpace(jwt.Payload.Amr))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10313, jwt));

            if (validationParameters.RequireAuthTime && string.IsNullOrWhiteSpace(jwt.Payload.AuthTime))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10314, jwt));

            if (validationParameters.RequireAzp && string.IsNullOrWhiteSpace(jwt.Payload.Azp))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10315, jwt));

            if (validationParameters.RequireNonce && string.IsNullOrWhiteSpace(validationContext.Nonce))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10311, jwt));

            if (!string.IsNullOrWhiteSpace(validationContext.Nonce))
                ValidateNonce(jwt, validationContext.Nonce);

            if (!string.IsNullOrWhiteSpace(validationContext.AuthorizationCode))
                ValidateCHash(jwt, validationContext.AuthorizationCode, validationParameters.AlgorithmMap);
        }

        /// <summary>
        /// Validates that the 'authorizationCode' according to http://openid.net/specs/openid-connect-core-1_0.html section 3.3.2.10
        /// </summary>
        /// <param name="jwt">the <see cref="JwtSecurityToken"/> that that should contain a matching 'c_hash' claim.</param>
        /// <param name="authorizationCode">the 'Authorization Code' to validate.</param>
        /// <param name="algorithmMap">a <see cref="IDictionary{TKey, TValue}"/> that contains mappings from the JWT namespace http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26 to .Net. Can be null.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'authorizationCode' is null or whitespace.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the <see cref="JwtSecurityToken"/> does not contain a 'c_hash' claim.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the 'c_hash' claim is null or whitespace.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the hash algorithm was unable to be created.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the creation of the hash algorithm return a null instance.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the 'c_hash' did not validate as per http://openid.net/specs/openid-connect-core-1_0.html#CodeValidation .</exception>
        public static void ValidateCHash(JwtSecurityToken jwt, string authorizationCode, IDictionary<string, string> algorithmMap)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException("authorizationCode");
            }

            HashAlgorithm hashAlgorithm = null;
            if (!jwt.Payload.ContainsKey(JwtRegisteredClaimNames.CHash))
            {
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10308, jwt));
            }

            string c_hashInToken = jwt.Payload[JwtRegisteredClaimNames.CHash] as string;
            if (c_hashInToken == null)
            {                
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10302, jwt));
            }

            if (string.IsNullOrWhiteSpace(c_hashInToken))
            {                
                throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10303, jwt));
            }

            string algorithm = string.Empty;
            if (!jwt.Header.TryGetValue(JwtHeaderParameterNames.Alg, out algorithm))
            {
                algorithm = JwtAlgorithms.RSA_SHA256;
            }

            if (algorithmMap != null)
            {
                string alg = string.Empty;
                if (algorithmMap.TryGetValue(algorithm, out alg))
                    algorithm = alg;
            }

            try
            {
                try
                {
                    hashAlgorithm = HashAlgorithm.Create(algorithm);
                }
                catch (Exception ex)
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10306, algorithm, jwt), ex);
                }

                if (hashAlgorithm == null)
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10306, algorithm, jwt));
                }

                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(authorizationCode));
                string hashString = Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
                if (!StringComparer.Ordinal.Equals(c_hashInToken, hashString))
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10304, c_hashInToken, authorizationCode, algorithm, jwt));
                }
            }
            finally
            {
                if (hashAlgorithm != null)
                {
                    hashAlgorithm.Dispose();
                }
            }
        }

        /// <summary>
        /// Validates that the <see cref="JwtSecurityToken"/> contains the nonce.
        /// </summary>
        /// <param name="jwt">the <see cref="JwtSecurityToken"/>that must contain the nonce.</param>
        /// <param name="nonce">the 'nonce' to match.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'nonce' is null or whitespace.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if a'nonce' is not found in the <see cref="JwtSecurityToken"/>.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if the 'nonce' found in the <see cref="JwtSecurityToken"/> is null or whitespace.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if the 'nonce' found in the <see cref="JwtSecurityToken"/> doesn't match the 'nonce' passed to routine.</exception>
        public static void ValidateNonce(JwtSecurityToken jwt, string nonce)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (string.IsNullOrWhiteSpace(nonce))
            {
                throw new ArgumentNullException("nonce");
            }

            string nonceFoundInJwt = jwt.Payload.Nonce;
            if (nonceFoundInJwt == null || string.IsNullOrWhiteSpace(nonceFoundInJwt))
            {
                throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10300, JwtRegisteredClaimNames.Nonce, jwt.ToString()));
            }

            if (!(StringComparer.Ordinal.Equals(nonceFoundInJwt, nonce)))
            {
                throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10301, nonceFoundInJwt, nonce, jwt.ToString()));
            }
        }
    }
}
