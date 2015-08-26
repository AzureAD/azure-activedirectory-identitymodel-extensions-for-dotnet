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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
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
            RequireState = true;
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
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10333);
            string nonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString() + Guid.NewGuid().ToString()));
            if (RequireTimeStampInNonce)
            {
                return DateTime.UtcNow.Ticks.ToString(CultureInfo.InvariantCulture) + "." + nonce;
            }

            return nonce;
        }

        /// <summary>
        /// Gets the algorithm mapping between OpenIdConnect and .Net for Hash algorithms.
        /// a <see cref="IDictionary{TKey, TValue}"/> that contains mappings from the JWT namespace http://tools.ietf.org/html/rfc7518 to .Net.
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
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10105, value), typeof(ArgumentOutOfRangeException), EventLevel.Error);
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
        /// Gets or sets a value indicating if a 'state' validation is required.
        /// </summary>
        [DefaultValue(true)]
        public bool RequireState { get; set; }

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
        /// Validates that an OpenIdConnect Response is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the response is not spec compliant.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the <see cref="OpenIdConnectProtocolValidationContext.IdToken"/> == null AND <see cref="OpenIdConnectProtocolValidationContext.ProtocolMessage.IdToken"/> != null. 
        /// This indicates the 'id_token' was not validated.</exception>
        /// <remarks>It is assumed that the IdToken has had basic validation performed.</remarks>
        public virtual void Validate(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // this means the 'id_token' was not validated
            if (validationContext.IdToken == null && validationContext.ProtocolMessage != null && !string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken))
            {
                LogHelper.Throw(LogMessages.IDX10331, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (validationContext.IdToken != null)
            {
                ValidateIdToken(validationContext.IdToken);
                ValidateCHash(validationContext);
                ValidateAtHash(validationContext);
                ValidateNonce(validationContext);
            }

            ValidateState(validationContext);
        }

        /// <summary>
        /// Validates that a <see cref="JwtSecurityToken"/> is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="idToken">the 'id_token' received in the OIDC response.</param>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the <see cref="JwtSecurityToken"/> is missing any required claims as per: http://openid.net/specs/openid-connect-core-1_0.html#IDToken </exception>
        /// <remarks>It is assumed that the IdToken has had basic validation performed.</remarks>
        /// Obsolete - Will be removed in beta8, use Validate(OpenIdConnectProtocolValidationContext validationContext)
        public virtual void Validate(JwtSecurityToken idToken, OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // this is temporary until beta8
            var newValidationContext = new OpenIdConnectProtocolValidationContext
            {
                AuthorizationCode = validationContext.AuthorizationCode,
                IdToken = validationContext.IdToken ?? idToken,
                ClientId = validationContext.ClientId,
                Nonce = validationContext.Nonce,
                ProtocolMessage = validationContext.ProtocolMessage,
                State = validationContext.State
            };

            if (newValidationContext.ProtocolMessage == null)
            {
                newValidationContext.ProtocolMessage = new OpenIdConnectMessage
                {
                    Code = newValidationContext.AuthorizationCode,
                };
            }

            Validate(newValidationContext);
        }

        protected virtual void ValidateIdToken(JwtSecurityToken idToken)
        {
            // required claims
            if (idToken.Payload.Aud.Count == 0)
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10309, JwtRegisteredClaimNames.Aud.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (!idToken.Payload.Exp.HasValue)
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10309, JwtRegisteredClaimNames.Exp.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (!idToken.Payload.Iat.HasValue)
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10309, JwtRegisteredClaimNames.Iat.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (idToken.Payload.Iss == null)
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10309, JwtRegisteredClaimNames.Iss.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            // sub is optional by default
            if (RequireSub && (string.IsNullOrWhiteSpace(idToken.Payload.Sub)))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10309, JwtRegisteredClaimNames.Sub.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            // optional claims
            if (RequireAcr && string.IsNullOrWhiteSpace(idToken.Payload.Acr))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10312, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (RequireAmr && string.IsNullOrWhiteSpace(idToken.Payload.Amr))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10313, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (RequireAuthTime && string.IsNullOrWhiteSpace(idToken.Payload.AuthTime))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            if (RequireAzp && string.IsNullOrWhiteSpace(idToken.Payload.Azp))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10315, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);
        }

        private HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            if (algorithm == null)
            {
                algorithm = JwtAlgorithms.RSA_SHA256;
            }

            try
            {
                switch (algorithm)
                {
                    case "SHA256":
                    case JwtAlgorithms.RSA_SHA256:
                    case JwtAlgorithms.ECDSA_SHA256:
                    case JwtAlgorithms.HMAC_SHA256:
                        return SHA256.Create();
                }

            }
            catch (Exception ex)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10306, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error, ex);
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10307, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error);

            return null;
        }

        /// <summary>
        /// Validates the 'token' or 'code' see: http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="expectedValue">the expected value of the hash. normally the c_hash or at_hash claim.</param>
        /// <param name="hashItem">item to be hashed per oidc spec.</param>
        /// <param name="algorithm">algorithm to use for compute hash.</param>
        /// <exception cref="OpenIdConnectProtocolException">if expected value does not equal the hashed value.</exception>
        private void ValidateHash(string expectedValue, string hashItem, string algorithm)
        {
            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10334, expectedValue));
            using (var hashAlgorithm = GetHashAlgorithm(algorithm))
            {
                var hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(hashItem));
                var hashString = Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
                if (!StringComparer.Ordinal.Equals(expectedValue, hashString))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10304, expectedValue, hashItem, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error);
                }
            }
        }

        /// <summary>
        /// Validates the 'code' according to http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the protocol message to validate.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the validationContext contains a 'code' and there is no 'c_hash' claim in the 'id_token'.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the validationContext contains a 'code' and the 'c_hash' claim is not a string in the 'id_token'.</exception> 
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the <see cref="OpenIdConnectProtocolValidationContext.IdToken"/> is null and <see cref="OpenIdConnectProtocolValidationContext.ProtocolMessage.IdToken"/> != null. This indicates the 'id_token' was not validated.</exception> 
        protected virtual void ValidateCHash(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10335);
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ProtocolMessage == null)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10336);
                return;
            }

            if (string.IsNullOrEmpty(validationContext.ProtocolMessage.Code))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10337);
                return;
            }

            if (validationContext.IdToken == null && string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10338);
                return;
            }

            // this means the 'id_token' was not validated
            if (validationContext.IdToken == null)
            {
                LogHelper.Throw(LogMessages.IDX10331, typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error);
            }

            object cHashClaim;
            if (!validationContext.IdToken.Payload.TryGetValue(JwtRegisteredClaimNames.CHash, out cHashClaim))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10308, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error);
            }

            var chash = cHashClaim as string;
            if (chash == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10326, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error);
            }

            try
            {
                ValidateHash(chash, validationContext.ProtocolMessage.Code, validationContext.IdToken.Header.Alg);
            }
            catch(OpenIdConnectProtocolException ex)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10329, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error, ex);
            }
        }

        /// <summary>
        /// Validates the 'token' according to http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the protocol message to validate.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidAtHashException">if the validationContext contains a 'token' and there is no 'at_hash' claim in the id_token.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidAtHashException">if the validationContext contains a 'token' and the 'at_hash' claim is not a string in the 'id_token'.</exception> 
        /// <exception cref="OpenIdConnectProtocolInvalidAtHashException">if the <see cref="OpenIdConnectProtocolValidationContext.IdToken"/> is null and <see cref="OpenIdConnectProtocolValidationContext.ProtocolMessage.IdToken"/> != null. This indicates the id_token was not validated.</exception> 
        protected virtual void ValidateAtHash(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10339);
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ProtocolMessage == null)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10336);
                return;
            }

            if (validationContext.ProtocolMessage.Token == null)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10340);
                return;
            }

            if (validationContext.IdToken == null && string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10341);
                return;
            }

            // this means the 'id_token' was not validated
            if (validationContext.IdToken == null)
            {
                LogHelper.Throw(LogMessages.IDX10331, typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error);
            }

            object atHashClaim;
            if (!validationContext.IdToken.Payload.TryGetValue("at_hash", out atHashClaim))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10324, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error);
            }

            var atHash = atHashClaim as string;
            if (atHash == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10325, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error);
            }

            try
            {
                ValidateHash(atHash, validationContext.ProtocolMessage.Token, validationContext.IdToken.Header.Alg);
            }
            catch (OpenIdConnectProtocolException ex)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10330, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error, ex);
            }
        }

        /// <summary>
        /// Validates that the <see cref="JwtSecurityToken"/> contains the nonce.
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the 'nonce' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if a 'nonce' is not found in the id_token and RequireNonce is true.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is null and RequireNonce is true.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if the 'nonce' found in the 'id_token' does not match <see cref="OpenIdConnectProtocolValidationContext.Nonce"/>.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="RequireTimeStampInNonce"/> is true and a timestamp is not: found, well formed, negatire or expired.</exception>
        /// <remarks>The timestamp is only validated if <see cref="RequireTimeStampInNonce"/> is true.
        /// <para>If <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is not-null, then a matching 'nonce' must exist in the 'id_token'.</para></remarks>
        protected virtual void ValidateNonce(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10342);

            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.IdToken == null)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10343);
                return;
            }

            string nonceFoundInJwt = validationContext.IdToken.Payload.Nonce;
            if (RequireNonce)
            {
                if (validationContext.Nonce == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10311), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }

                if (nonceFoundInJwt == null)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10322, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }
            }
            else if ((validationContext.Nonce != null) && (nonceFoundInJwt == null))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10323, validationContext.Nonce, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
            }
            else if (validationContext.Nonce == null)
            {
                IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX10344);
                return;
            }

            if (!(StringComparer.Ordinal.Equals(nonceFoundInJwt, validationContext.Nonce)))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10301, nonceFoundInJwt, validationContext.Nonce, validationContext.IdToken), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
            }

            if (RequireTimeStampInNonce)
            {
                int endOfTimestamp = nonceFoundInJwt.IndexOf('.');
                if (endOfTimestamp == -1)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10317, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }

                string timestamp = nonceFoundInJwt.Substring(0, endOfTimestamp);
                DateTime nonceTime = new DateTime(1979, 1, 1);          // initializing to some value otherwise it gives an error
                long ticks = -1;
                try
                {
                    ticks = Convert.ToInt64(timestamp, CultureInfo.InvariantCulture);
                }
                catch (Exception ex)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10318, timestamp, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error, ex);
                }

                if (ticks <= 0)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10318, timestamp, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }

                try
                {
                    nonceTime = DateTime.FromBinary(ticks);
                }
                catch(Exception ex)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10320, timestamp, System.DateTime.MinValue.Ticks.ToString(CultureInfo.InvariantCulture), System.DateTime.MaxValue.Ticks.ToString(CultureInfo.InvariantCulture)), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error, ex);
                }

                DateTime utcNow = DateTime.UtcNow;
                if (nonceTime + NonceLifetime < utcNow)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10316, validationContext.Nonce, nonceTime.ToString(), utcNow.ToString(), NonceLifetime.ToString()), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }
            }
        }

        /// <summary>
        /// Validates that the 'state' in message is valid.
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the 'state' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidStateException">if 'state' in the context does not match the state in the message.</exception>
        protected virtual void ValidateState(OpenIdConnectProtocolValidationContext validationContext)
        {

            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // if state is missing, but not required just return. Otherwise process it.
            if (string.IsNullOrEmpty(validationContext.State))
            {
                if (RequireState)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10332, GetType() + ": validationContext"), typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
                }
                else
                {
                    return;
                }
            }

            // 'state' was sent, but message does not contain 'state'
            if (validationContext.ProtocolMessage == null || string.IsNullOrEmpty(validationContext.ProtocolMessage.State))
            {
                LogHelper.Throw(LogMessages.IDX10327, typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
            }

            if (!string.Equals(validationContext.State, validationContext.ProtocolMessage.State, StringComparison.Ordinal))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10328, validationContext.State, validationContext.ProtocolMessage.State), typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
            }
        }
    }
}
