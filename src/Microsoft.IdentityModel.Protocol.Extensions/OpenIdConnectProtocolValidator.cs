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
using System.ComponentModel;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// OpenIdConnectProtocolValidator can be used to ensure that a <see cref="JwtSecurityToken"/> that was
    /// obtained using openidconnect is compliant with  http://openid.net/specs/openid-connect-core-1_0.html#IDToken .
    /// </summary>
    public class OpenIdConnectProtocolValidator
    {
        private IDictionary<string, string> _hashAlgorithmMap =
            new Dictionary<string, string>
            {
                { JwtAlgorithms.ECDSA_SHA256, "SHA256" },
                { JwtAlgorithms.RSA_SHA256, "SHA256" },
                { JwtAlgorithms.HMAC_SHA256, "SHA256" },
                { JwtAlgorithms.ECDSA_SHA384, "SHA384" },
                { JwtAlgorithms.RSA_SHA384, "SHA384" },
                { JwtAlgorithms.HMAC_SHA384, "SHA384" },
                { JwtAlgorithms.ECDSA_SHA512, "SHA512" },
                { JwtAlgorithms.RSA_SHA512, "SHA512" },
                { JwtAlgorithms.HMAC_SHA512, "SHA512" },
          };
        private TimeSpan _nonceLifetime = DefaultNonceLifetime;

        /// <summary>
        /// Default for the how long the nonce is valid.
        /// </summary>
        /// <remarks>default: 1 hour.</remarks>
        public static readonly TimeSpan DefaultNonceLifetime = TimeSpan.FromMinutes(60);

        /// <summary>
        /// Creates a new instance of <see cref="OpenIdConnectProtocolValidator"/>,
        /// </summary>
        public OpenIdConnectProtocolValidator()
        {
            RequireAcr = false;
            RequireAmr = false;
            RequireAuthTime = false;
            RequireAzp = false;
            RequireNonce = true;
            RequireSub = false;
            RequireTimeStampInNonce = true;
        }

        /// <summary>
        /// Generates a value suitable to use as a nonce.
        /// </summary>
        /// <returns>a nonce</returns>
        /// <remarks>if <see cref="RequireTimeStampInNonce"/> is true then the 'nonce' will contain the Epoch time as the prefix, seperated by a '.'.
        /// <para>for example: 635410359229176103.MjQxMzU0ODUtMTdiNi00NzAwLWE4MjYtNTE4NGExYmMxNTNlZmRkOGU4NjctZjQ5OS00MWIyLTljNTEtMjg3NmM0NzI4ZTc5</para></remarks>
        public virtual string GenerateNonce()
        {
            string nonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString() + Guid.NewGuid().ToString()));
            if (RequireTimeStampInNonce)
            {
                return DateTime.UtcNow.Ticks.ToString(CultureInfo.InvariantCulture) + "." + nonce;
            }

            return nonce;
        }

        /// <summary>
        /// Gets the algorithm mapping between OpenIdConnect and .Net for Hash algorithms.
        /// a <see cref="IDictionary{TKey, TValue}"/> that contains mappings from the JWT namespace http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26 to .Net.
        /// </summary>
        public IDictionary<string, string> HashAlgorithmMap
        {
            get
            {
                return _hashAlgorithmMap;
            }
        }

        /// <summary>
        /// Gets or set the <see cref="TimeSpan"/> defining how long a nonce is valid.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">if 'value' is less than or equal to 'TimeSpan.Zero'.</exception>
        /// <remarks>if <see cref="RequireTimeStampInNonce"/> is true, then the nonce timestamp is bound by DateTime.UtcNow + NonceLifetime.</remarks>
        public TimeSpan NonceLifetime
        {
            get
            {
                return _nonceLifetime;
            }

            set
            {
                if (value <= TimeSpan.Zero)
                {
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10105, value));
                }

                _nonceLifetime = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating if an 'acr' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAcr { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'amr' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAmr { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'auth_time' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAuthTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'azp' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAzp { get; set; }

        /// <summary>
        /// Get or sets if a nonce is required.
        /// </summary>
        [DefaultValue(true)]
        public bool RequireNonce { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if a 'sub' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireSub { get; set; }

        /// <summary>
        /// Gets or set logic to control if a nonce is prefixed with a timestamp.
        /// </summary>
        /// <remarks>if <see cref="RequireTimeStampInNonce"/> is true then:
        /// <para><see cref="GenerateNonce"/> will return a 'nonce' with the Epoch time as the prefix, delimited with a '.'.</para>
        /// <para><see cref="ValidateNonce"/> will require that the 'nonce' has a valid time as the prefix.</para>
        /// </remarks>
        [DefaultValue(true)]
        public bool RequireTimeStampInNonce { get; set; }

        /// <summary>
        /// Validates that a <see cref="JwtSecurityToken"/> is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="jwt">the <see cref="JwtSecurityToken"/>to validate.</param>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the <see cref="JwtSecurityToken"/> is missing any required claims as per: http://openid.net/specs/openid-connect-core-1_0.html#IDToken </exception>
        /// <remarks><see cref="OpenIdConnectProtocolValidationContext.Nonce"/> and <see cref="OpenIdConnectProtocolValidationContext.AuthorizationCode"/> will be validated if they are non-null.</remarks>
        public virtual void Validate(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext)
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

            // sub is optional by default
            if (RequireSub && (string.IsNullOrWhiteSpace(jwt.Payload.Sub)))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10309, JwtRegisteredClaimNames.Sub.ToLowerInvariant(), jwt));

            // optional claims
            if (RequireAcr && string.IsNullOrWhiteSpace(jwt.Payload.Acr))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10312, jwt));

            if (RequireAmr && string.IsNullOrWhiteSpace(jwt.Payload.Amr))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10313, jwt));

            if (RequireAuthTime && string.IsNullOrWhiteSpace(jwt.Payload.AuthTime))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10314, jwt));

            if (RequireAzp && string.IsNullOrWhiteSpace(jwt.Payload.Azp))
                throw new OpenIdConnectProtocolException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10315, jwt));

            ValidateNonce(jwt, validationContext);
            ValidateCHash(jwt, validationContext);
        }

        /// <summary>
        /// Validates the 'authorizationCode' according to http://openid.net/specs/openid-connect-core-1_0.html section 3.3.2.10.
        /// </summary>
        /// <param name="jwt">a <see cref="JwtSecurityToken"/> with a 'c_hash' claim that must match <see cref="OpenIdConnectProtocolValidationContext.AuthorizationCode"/>. If <see cref="OpenIdConnectProtocolValidationContext.AuthorizationCode"/> is null, the check is not made.</param>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains 'c_hash' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the <see cref="JwtSecurityToken"/> 'c_hash' claim does not match <see cref="OpenIdConnectProtocolValidationContext.AuthorizationCode"/> as per http://openid.net/specs/openid-connect-core-1_0.html#CodeValidation .</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the hash algorithm defined in <see cref="JwtHeader"/> (default is JwtAlgorithms.RSA_SHA256) was unable to be created.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the creation of the hash algorithm return a null instance.</exception>
        /// <remarks>if <see cref="OpenIdConnectProtocolValidationContext.AuthorizationCode"/> is null, then the <see cref="JwtSecurityToken"/> 'c_hash' will not be validated.</remarks>
        protected virtual void ValidateCHash(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (validationContext == null)
            {
                throw new ArgumentNullException("validationContext");
            }

            // this handles the case the code is not expected
            if (validationContext.AuthorizationCode == null)
            {
                return;
            }

            if (!jwt.Payload.ContainsKey(JwtRegisteredClaimNames.CHash))
            {
                return;
            }

            HashAlgorithm hashAlgorithm = null;
            string algorithm = jwt.Header.Alg;
            if (algorithm == null)
            {
                algorithm = JwtAlgorithms.RSA_SHA256;
            }

            string alg = string.Empty;
            if (HashAlgorithmMap.TryGetValue(algorithm, out alg))
            {
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
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10307, algorithm, jwt));
                }

                byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(validationContext.AuthorizationCode));
                string hashString = Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
                if (!StringComparer.Ordinal.Equals(jwt.Payload.CHash, hashString))
                {
                    throw new OpenIdConnectProtocolInvalidCHashException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10304, jwt.Payload.CHash, validationContext.AuthorizationCode, algorithm, jwt));
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
        /// <param name="jwt">a <see cref="JwtSecurityToken"/> with a 'nonce' claim that must match <see cref="OpenIdConnectProtocolValidationContext.Nonce"/>.</param>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the 'nonce' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if a'nonce' is not found in the <see cref="JwtSecurityToken"/> and RequireNonce is true.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is null and RequireNonce is true.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if the 'nonce' found in the <see cref="JwtSecurityToken"/> doesn't match <see cref="OpenIdConnectProtocolValidationContext.Nonce"/>.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="RequireTimeStampInNonce"/> is true and a timestamp is not: found, well formed, negatire or expired.</exception>
        /// <remarks>The timestamp is only validated if <see cref="RequireTimeStampInNonce"/> is true.
        /// <para>If <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is not-null, then a matching 'nonce' must exist in the <see cref="JwtSecurityToken"/>.</para></remarks>
        protected virtual void ValidateNonce(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (validationContext == null)
            {
                throw new ArgumentNullException("validationContext");
            }

            string nonceFoundInJwt = jwt.Payload.Nonce;

            if (RequireNonce)
            {
                if (validationContext.Nonce == null)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10311));
                }

                if (nonceFoundInJwt == null)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10322, jwt.ToString()));
                }
            }
            else if ((validationContext.Nonce != null) && (nonceFoundInJwt == null))
            {
                throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10323, validationContext.Nonce, jwt.ToString()));
            }
            else if (validationContext.Nonce == null)
            {
                return;
            }

            if (!(StringComparer.Ordinal.Equals(nonceFoundInJwt, validationContext.Nonce)))
            {
                throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10301, validationContext.Nonce, nonceFoundInJwt, jwt.ToString()));
            }

            if (RequireTimeStampInNonce)
            {
                int endOfTimestamp = nonceFoundInJwt.IndexOf('.');
                if (endOfTimestamp == -1)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10317, validationContext.Nonce));
                }

                string timestamp = nonceFoundInJwt.Substring(0, endOfTimestamp);
                DateTime nonceTime;
                long ticks;
                try
                {
                    ticks = Convert.ToInt64(timestamp, CultureInfo.InvariantCulture);
                }
                catch (Exception ex)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10318, timestamp, validationContext.Nonce), ex);
                }

                if (ticks <= 0)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10318, timestamp, validationContext.Nonce));
                }

                try
                {
                    nonceTime = DateTime.FromBinary(ticks);
                }
                catch(Exception ex)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10320, timestamp, System.DateTime.MinValue.Ticks.ToString(CultureInfo.InvariantCulture), System.DateTime.MaxValue.Ticks.ToString(CultureInfo.InvariantCulture)), ex);
                }

                DateTime utcNow = DateTime.UtcNow;
                if (nonceTime + NonceLifetime < utcNow)
                {
                    throw new OpenIdConnectProtocolInvalidNonceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10316, validationContext.Nonce, nonceTime.ToString(), utcNow.ToString(), NonceLifetime.ToString()));
                }
            }
        }
    }
}
