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
    /// Delegate for validating additional claims in 'id_token' 
    /// </summary>
    /// <param name="idToken"><see cref="JwtSecurityToken"/> to validate</param>
    /// <param name="context"><see cref="OpenIdConnectProtocolValidationContext"/> used for validation</param>
    public delegate void IdTokenValidator(JwtSecurityToken idToken, OpenIdConnectProtocolValidationContext context);

    /// <summary>
    /// <see cref="OpenIdConnectProtocolValidator"/> is used to ensure that an <see cref="OpenIdConnectMessage"/>
    ///  obtained using OpenIdConnect is compliant with  http://openid.net/specs/openid-connect-core-1_0.html .
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
            RequireStateValidation = true;
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
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10328);
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
        public bool RequireStateValidation { get; set; }

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
        /// Gets or sets the delegate for validating 'id_token'
        /// </summary>
        public IdTokenValidator IdTokenValidator { get; set; }

        /// <summary>
        /// Validates that an OpenIdConnect Response from 'authorization_endpoint" is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the response is not spec compliant.</exception>
        /// <remarks>It is assumed that the IdToken had ('aud', 'iss', 'signature', 'lifetime') validated.</remarks>
        public virtual void ValidateAuthenticationResponse(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // no 'response' is recieved or 'id_token' in the response is null 
            if (validationContext.ProtocolMessage == null)
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken))
            {
                // if 'code' is also not present, then throw.
                if (string.IsNullOrEmpty(validationContext.ProtocolMessage.Code))
                {
                    LogHelper.Throw(LogMessages.IDX10334, typeof(OpenIdConnectProtocolException), EventLevel.Error);
                }
                else
                {
                    ValidateState(validationContext);
                }
                return;
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(LogMessages.IDX10331, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            // 'refresh_token' should not be returned from 'authorization_endpoint'. http://tools.ietf.org/html/rfc6749#section-4.2.2.
            if (!string.IsNullOrEmpty(validationContext.ProtocolMessage.RefreshToken))
            {
                LogHelper.Throw(LogMessages.IDX10335, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            ValidateState(validationContext);
            ValidateIdToken(validationContext);
            ValidateNonce(validationContext);
            ValidateCHash(validationContext);
            ValidateAtHash(validationContext);
        }

        /// <summary>
        /// Validates that an OpenIdConnect Response from "token_endpoint" is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the response is not spec compliant.</exception>
        /// <remarks>It is assumed that the IdToken had ('aud', 'iss', 'signature', 'lifetime') validated.</remarks>
        public virtual void ValidateTokenResponse(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // no 'response' is recieved 
            if (validationContext.ProtocolMessage == null)
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            // both 'id_token' and 'token' are required
            if (string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken) || string.IsNullOrEmpty(validationContext.ProtocolMessage.Token))
            {
                LogHelper.Throw(LogMessages.IDX10336, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(LogMessages.IDX10331, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            ValidateIdToken(validationContext);
            ValidateNonce(validationContext);


            // only if 'at_hash' claim exist. 'at_hash' is not required in token response.
            object atHashClaim;
            if (validationContext.ValidatedIdToken.Payload.TryGetValue(JwtRegisteredClaimNames.AtHash, out atHashClaim))
            {
                ValidateAtHash(validationContext);
            }

        }

        /// <summary>
        /// Validates that an OpenIdConnect Response from "useinfo_endpoint" is valid as per http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolException">if the response is not spec compliant.</exception>
        public virtual void ValidateUserInfoResponse(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // no 'response' is recieved or 'id_token' in the response is null 
            if (validationContext.ProtocolMessage == null || string.IsNullOrEmpty(validationContext.ProtocolMessage.IdToken))
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (validationContext.UserInfoEndpointResponse == null)
            {
                LogHelper.Throw(LogMessages.IDX10337, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(LogMessages.IDX10332, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            string idTokenSubject = validationContext.ValidatedIdToken.Payload.Sub;
            string userInfoSubject = validationContext.UserInfoEndpointResponse.Payload.Sub;

            if (!string.Equals(idTokenSubject, userInfoSubject, StringComparison.Ordinal))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10338, idTokenSubject, userInfoSubject), typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }
        }

        /// <summary>
        /// Validates the claims in the 'id_token' as per http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        /// </summary>
        /// <param name="validationContext">the <see cref="OpenIdConnectProtocolValidationContext"/> that contains expected values.</param>
        protected virtual void ValidateIdToken(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext.ValidatedIdToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }


            // if user sets the custom validator, we call the delegate. The default checks for multiple audiences and azp are not executed.
            if (this.IdTokenValidator != null)
            {
                try
                {
                    this.IdTokenValidator(validationContext.ValidatedIdToken, validationContext);
                }
                catch (OpenIdConnectProtocolException ex)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10313, validationContext.ValidatedIdToken, ex.Message), ex.GetType(), EventLevel.Error);
                }
                return;
            }
            else
            {
                JwtSecurityToken idToken = validationContext.ValidatedIdToken;

                // required claims
                if (idToken.Payload.Aud.Count == 0)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, JwtRegisteredClaimNames.Aud.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (!idToken.Payload.Exp.HasValue)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, JwtRegisteredClaimNames.Exp.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (!idToken.Payload.Iat.HasValue)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, JwtRegisteredClaimNames.Iat.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (idToken.Payload.Iss == null)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, JwtRegisteredClaimNames.Iss.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                // sub is optional by default
                if (RequireSub && (string.IsNullOrWhiteSpace(idToken.Payload.Sub)))
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10314, JwtRegisteredClaimNames.Sub.ToLowerInvariant(), idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                // optional claims
                if (RequireAcr && string.IsNullOrWhiteSpace(idToken.Payload.Acr))
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10315, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (RequireAmr && string.IsNullOrWhiteSpace(idToken.Payload.Amr))
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10316, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (RequireAuthTime && !(idToken.Payload.AuthTime.HasValue))
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10317, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                if (RequireAzp && string.IsNullOrWhiteSpace(idToken.Payload.Azp))
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10318, idToken), typeof(OpenIdConnectProtocolException), EventLevel.Error);

                // if multiple audiences are present in the id_token, 'azp' claim should be present
                if (idToken.Payload.Aud.Count > 1 && string.IsNullOrEmpty(idToken.Payload.Azp))
                {
                    IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX10339);
                }

                // if 'azp' claim exist, it should be equal to 'client_id' of the application
                if (!string.IsNullOrEmpty(idToken.Payload.Azp))
                {
                    if (string.IsNullOrEmpty(validationContext.ClientId))
                    {
                        LogHelper.Throw(LogMessages.IDX10308, typeof(OpenIdConnectProtocolException), EventLevel.Error);
                    }
                    else if (!string.Equals(idToken.Payload.Azp, validationContext.ClientId, StringComparison.Ordinal))
                    {
                        LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10340, idToken.Payload.Azp, validationContext.ClientId), typeof(OpenIdConnectProtocolException), EventLevel.Error);
                    }
                }
            }
        }

        /// <summary>
        /// Returns the implementation corresponding to the input string 'algorithm'.
        /// </summary>
        /// <param name="algorithm">string representing the hash algorithm</param>
        /// <returns><see cref="HashAlgorithm"/> corresponding to the input string 'algorithm'</returns>
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
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10301, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error, ex);
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10302, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error);

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
            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10303, expectedValue));
            using (var hashAlgorithm = GetHashAlgorithm(algorithm))
            {
                var hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(hashItem));
                var hashString = Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
                if (!string.Equals(expectedValue, hashString, StringComparison.Ordinal))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10300, expectedValue, hashItem, algorithm), typeof(OpenIdConnectProtocolException), EventLevel.Error);
                }
            }
        }

        /// <summary>
        /// Validates the 'code' according to http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the protocol message to validate.</param>
        /// <exception cref="ArgumentNullException">if 'idToken' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the validationContext contains a 'code' and there is no 'c_hash' claim in the 'id_token'.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the validationContext contains a 'code' and the 'c_hash' claim is not a string in the 'id_token'.</exception> 
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the 'c_hash' claim in the 'idToken' does not correspond to the 'code' in the <see cref="OpenIdConnectMessage"/> response.</exception> 
        protected virtual void ValidateCHash(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10304);

            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext.ValidatedIdToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ProtocolMessage == null)
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (string.IsNullOrEmpty(validationContext.ProtocolMessage.Code))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10305);
                return;
            }

            object cHashClaim;
            if (!validationContext.ValidatedIdToken.Payload.TryGetValue(JwtRegisteredClaimNames.CHash, out cHashClaim))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10307, validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error);
            }

            var chash = cHashClaim as string;
            if (chash == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10306, validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error);
            }

            try
            {
                ValidateHash(chash, validationContext.ProtocolMessage.Code, validationContext.ValidatedIdToken.Header.Alg);
            }
            catch(OpenIdConnectProtocolException ex)
            {
                LogHelper.Throw(ex.Message, typeof(OpenIdConnectProtocolInvalidCHashException), EventLevel.Error, ex);
            }
        }

        /// <summary>
        /// Validates the 'token' according to http://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the protocol message to validate.</param>
        /// <exception cref="ArgumentNullException">if 'idToken' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidAtHashException">if the validationContext contains a 'token' and there is no 'at_hash' claim in the id_token.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidAtHashException">if the validationContext contains a 'token' and the 'at_hash' claim is not a string in the 'id_token'.</exception> 
        /// <exception cref="OpenIdConnectProtocolInvalidCHashException">if the 'at_hash' claim in the 'idToken' does not correspond to the 'token' in the <see cref="OpenIdConnectMessage"/> response.</exception> 
        protected virtual void ValidateAtHash(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10309);

            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext.ValidatedIdToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ProtocolMessage == null)
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            if (validationContext.ProtocolMessage.Token == null)
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10310);
                return;
            }

            object atHashClaim;
            if (!validationContext.ValidatedIdToken.Payload.TryGetValue(JwtRegisteredClaimNames.AtHash, out atHashClaim))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10312, validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error);
            }

            var atHash = atHashClaim as string;
            if (atHash == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10311, validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error);
            }

            try
            {
                ValidateHash(atHash, validationContext.ProtocolMessage.Token, validationContext.ValidatedIdToken.Header.Alg);
            }
            catch (OpenIdConnectProtocolException ex)
            {
                LogHelper.Throw(ex.Message, typeof(OpenIdConnectProtocolInvalidAtHashException), EventLevel.Error, ex);
            }
        }

        /// <summary>
        /// Validates that the <see cref="JwtSecurityToken"/> contains the nonce.
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the 'nonce' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'idToken' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is null and RequireNonce is true.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if the 'nonce' found in the 'id_token' does not match <see cref="OpenIdConnectProtocolValidationContext.Nonce"/>.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidNonceException">if <see cref="RequireTimeStampInNonce"/> is true and a timestamp is not: found, well formed, negatire or expired.</exception>
        /// <remarks>The timestamp is only validated if <see cref="RequireTimeStampInNonce"/> is true.
        /// <para>If <see cref="OpenIdConnectProtocolValidationContext.Nonce"/> is not-null, then a matching 'nonce' must exist in the 'id_token'.</para></remarks>
        protected virtual void ValidateNonce(OpenIdConnectProtocolValidationContext validationContext)
        {
            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10319);

            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ValidatedIdToken == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext.ValidatedIdToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }
            string nonceFoundInJwt = validationContext.ValidatedIdToken.Payload.Nonce;

            if (!RequireNonce && string.IsNullOrEmpty(validationContext.Nonce) && string.IsNullOrEmpty(nonceFoundInJwt))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10322);
                return;
            }
            else if (string.IsNullOrEmpty(validationContext.Nonce))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10320, RequireNonce.ToString()), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);

            }
            else if (string.IsNullOrEmpty(nonceFoundInJwt))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10323, RequireNonce.ToString(), validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
            }

            if (!string.Equals(nonceFoundInJwt, validationContext.Nonce, StringComparison.Ordinal))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10321, validationContext.Nonce, nonceFoundInJwt, validationContext.ValidatedIdToken), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
            }

            if (RequireTimeStampInNonce)
            {
                int endOfTimestamp = nonceFoundInJwt.IndexOf('.');
                if (endOfTimestamp == -1)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10325, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
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
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10326, timestamp, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error, ex);
                }

                if (ticks <= 0)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10326, timestamp, validationContext.Nonce), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }

                try
                {
                    nonceTime = DateTime.FromBinary(ticks);
                }
                catch(Exception ex)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10327, timestamp, System.DateTime.MinValue.Ticks.ToString(CultureInfo.InvariantCulture), System.DateTime.MaxValue.Ticks.ToString(CultureInfo.InvariantCulture)), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error, ex);
                }

                DateTime utcNow = DateTime.UtcNow;
                if (nonceTime + NonceLifetime < utcNow)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10324, validationContext.Nonce, nonceTime.ToString(), utcNow.ToString(), NonceLifetime.ToString()), typeof(OpenIdConnectProtocolInvalidNonceException), EventLevel.Error);
                }
            }
        }

        /// <summary>
        /// Validates that the 'state' in message is valid.
        /// </summary>
        /// <param name="validationContext">a <see cref="OpenIdConnectProtocolValidationContext"/> that contains the 'state' to validate.</param>
        /// <exception cref="ArgumentNullException">if 'validationContext' is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidStateException">if 'state' is present in <see cref="OpenIdConnectProtocolValidationContext.State"/> but either <see cref="OpenIdConnectProtocolValidationContext.ProtocolMessage"/> or <see cref="OpenIdConnectProtocolValidationContext.ProtocolMessage.State"/> is null.</exception>
        /// <exception cref="OpenIdConnectProtocolInvalidStateException">if 'state' in the context does not match the state in the message.</exception>
        protected virtual void ValidateState(OpenIdConnectProtocolValidationContext validationContext)
        {
            if (validationContext == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": validationContext"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationContext.ProtocolMessage == null)
            {
                LogHelper.Throw(LogMessages.IDX10333, typeof(OpenIdConnectProtocolException), EventLevel.Error);
            }

            // if state is missing, but not required just return. Otherwise process it.
            if (!RequireStateValidation && string.IsNullOrEmpty(validationContext.State) && string.IsNullOrEmpty(validationContext.ProtocolMessage.State))
            {
                IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10341);
                return;
            }
            else if (string.IsNullOrEmpty(validationContext.State))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10329, RequireStateValidation.ToString()), typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
            }
            else if (string.IsNullOrEmpty(validationContext.ProtocolMessage.State))
            {
                // 'state' was sent, but message does not contain 'state'
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10330, RequireStateValidation.ToString()), typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
            }

            if (!string.Equals(validationContext.State, validationContext.ProtocolMessage.State, StringComparison.Ordinal))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10331, validationContext.State, validationContext.ProtocolMessage.State), typeof(OpenIdConnectProtocolInvalidStateException), EventLevel.Error);
            }
        }
    }
}
