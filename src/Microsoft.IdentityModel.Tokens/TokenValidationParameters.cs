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

namespace Microsoft.IdentityModel.Tokens
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Globalization;
    using System.Security.Claims;

    /// <summary>
    /// Definition for AudienceValidator.
    /// </summary>
    /// <param name="audiences">The audiences found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    public delegate bool AudienceValidator(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Definition for IssuerSigningKeyRetriever. When validating signatures, this method will return key to use.
    /// </summary>
    /// <param name="token">the <see cref="string"/> representation of the token that is being validated.</param>
    /// <param name="securityToken">the <SecurityToken> that is being validated. It may be null.</SecurityToken></param>
    /// <param name="kid">a key identifier. It may be null.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <returns></returns>
    public delegate SecurityKey IssuerSigningKeyResolver(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters);

    /// <summary>
    /// Definition for IssuerValidator.
    /// </summary>
    /// <param name="issuer">The issuer to validate.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    /// <returns>The issuer to use when creating the "Claim"(s) in a "ClaimsIdentity".</returns>
    public delegate string IssuerValidator(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Definition for LifetimeValidator.
    /// </summary>
    /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
    public delegate bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters);

    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    public class TokenValidationParameters
    {
        private string _authenticationType;
        private IList<SecurityToken> _clientDecryptionTokens = new List<SecurityToken>();
        private TimeSpan _clockSkew = DefaultClockSkew;
        private string _nameClaimType = ClaimsIdentity.DefaultNameClaimType;
        private string _roleClaimType = ClaimsIdentity.DefaultRoleClaimType;

        /// <summary>
        /// This is the fallback authenticationtype that a <see cref="ISecurityTokenValidator"/> will use if nothing is set.
        /// </summary>
        public static readonly string DefaultAuthenticationType = "AuthenticationTypes.Federation";

        /// <summary>
        /// Default for the clock skew.
        /// </summary>
        /// <remarks>300 seconds (5 minutes).</remarks>
        public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromSeconds(300); // 5 min.

        /// <summary>
        /// Default for the maximm token size.
        /// </summary>
        /// <remarks>2 MB (mega bytes).</remarks>
        public const Int32 DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2meg.

        /// <summary>
        /// Copy constructor for <see cref="TokenValidationParameters"/>.
        /// </summary>
        protected TokenValidationParameters(TokenValidationParameters other)
        {
            if (other == null)
            {
                throw new ArgumentNullException("other");
            }

            AudienceValidator = other.AudienceValidator;
            _authenticationType = other._authenticationType;
            ClockSkew = other.ClockSkew;
            ClientDecryptionTokens = other.ClientDecryptionTokens;
            IssuerSigningKey = other.IssuerSigningKey;
            IssuerSigningKeyResolver = other.IssuerSigningKeyResolver;
            IssuerSigningKeys = other.IssuerSigningKeys;
            IssuerSigningKeyValidator = other.IssuerSigningKeyValidator;
            IssuerValidator = other.IssuerValidator;
            LifetimeValidator = other.LifetimeValidator;
            NameClaimType = other.NameClaimType;
            NameClaimTypeRetriever = other.NameClaimTypeRetriever;
            RequireExpirationTime = other.RequireExpirationTime;
            RequireSignedTokens = other.RequireSignedTokens;
            RoleClaimType = other.RoleClaimType;
            RoleClaimTypeRetriever = other.RoleClaimTypeRetriever;
            SaveSigninToken = other.SaveSigninToken;
            //TokenReplayCache = other.TokenReplayCache;
            ValidateActor = other.ValidateActor;
            ValidateAudience = other.ValidateAudience;
            ValidateIssuer = other.ValidateIssuer;
            ValidateIssuerSigningKey = other.ValidateIssuerSigningKey;
            ValidateLifetime = other.ValidateLifetime;
            ValidAudience = other.ValidAudience;
            ValidAudiences = other.ValidAudiences;
            ValidIssuer = other.ValidIssuer;
            ValidIssuers = other.ValidIssuers;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParameters"/> class.
        /// </summary>        
        public TokenValidationParameters()
        {
            RequireExpirationTime = true;
            RequireSignedTokens = true;
            SaveSigninToken = false;
            ValidateActor = false;
            ValidateAudience = true;
            ValidateIssuer = true;
            ValidateIssuerSigningKey = false;
            ValidateLifetime = true;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the audience of the tokens
        /// </summary>
        public AudienceValidator AudienceValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the AuthenticationType when creating a <see cref="ClaimsIdentity"/> during token validation.
        /// </summary>
        /// <exception cref="ArgumentNullException"> if 'value' is null or whitespace.</exception>
        public string AuthenticationType
        {
            get
            {
                return _authenticationType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException("AuthenticationType");
                }

                _authenticationType = value;
            }
        }

        ///// <summary>
        ///// Gets or sets the <see cref="X509CertificateValidator"/> for validating X509Certificate2(s).
        ///// </summary>
        //public X509CertificateValidator CertificateValidator
        //{
        //    get
        //    {
        //        return _certificateValidator;
        //    }

        //    set
        //    {
        //        _certificateValidator = value;
        //    }
        //}

        /// <summary>
        /// Gets or sets the <see cref="ReadOnlyCollection{SecurityToken}"/> that is to be used for decrypting inbound tokens.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public IList<SecurityToken> ClientDecryptionTokens
        {
            get
            {
                return _clientDecryptionTokens;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("ClientDecryptionTokens");

                _clientDecryptionTokens = value;
            }
        }

        /// <summary>
        /// Gets or sets the clock skew to apply when validating times
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"> if 'value' is less than 0.</exception>
        [DefaultValue(300)]
        public TimeSpan ClockSkew
        {
            get
            {
                return _clockSkew;
            }

            set
            {
                if (value < TimeSpan.Zero)
                {
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10100, value));
                }

                _clockSkew = value;
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="TokenValidationParameters"/> with values copied from this object.
        /// </summary>
        /// <returns>A new <see cref="TokenValidationParameters"/> object copied from this object</returns>
        /// <remarks>This is a shallow Clone.</remarks>
        public virtual TokenValidationParameters Clone()
        {
            return new TokenValidationParameters(this);
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> using:
        /// <para><see cref="AuthenticationType"/></para>
        /// <para>'NameClaimType' is calculated: If NameClaimTypeRetriever call that else use NameClaimType. If the result is a null or empty string, use <see cref="ClaimsIdentity.DefaultNameClaimType"/></para>.
        /// <para>'RoleClaimType' is calculated: If RoleClaimTypeRetriever call that else use RoleClaimType. If the result is a null or empty string, use <see cref="ClaimsIdentity.DefaultRoleClaimType"/></para>.
        /// </summary>
        /// <returns>A <see cref="ClaimsIdentity"/> with Authentication, NameClaimType and RoleClaimType set.</returns>
        public virtual ClaimsIdentity CreateClaimsIdentity(SecurityToken securityToken, string issuer)
        {
            string nameClaimType = null;
            if (NameClaimTypeRetriever != null)
            {
                nameClaimType = NameClaimTypeRetriever(securityToken, issuer);
            }
            else
            {
                nameClaimType = NameClaimType;
            }

            string roleClaimType = null;
            if (RoleClaimTypeRetriever != null)
            {
                roleClaimType = RoleClaimTypeRetriever(securityToken, issuer);
            }
            else
            {
                roleClaimType = RoleClaimType;
            }

            return new ClaimsIdentity(authenticationType: AuthenticationType ?? DefaultAuthenticationType, nameType: nameClaimType ?? ClaimsIdentity.DefaultNameClaimType, roleType: roleClaimType ?? ClaimsIdentity.DefaultRoleClaimType);
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that is to be used for validating signed tokens. 
        /// </summary>
        public Action<SecurityKey> IssuerSigningKeyValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that is to be used for validating signed tokens. 
        /// </summary>
        public SecurityKey IssuerSigningKey
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to retreive <see cref="SecurityKey"/>(s) used for checking signatures.
        /// </summary>
        /// <remarks>Each <see cref="SecurityKey"/> will be used to check the signature. Returning multiple key can be helpful when the <see cref="SecurityToken"/> does not contain a key identifier. 
        /// This can occur when the issuer has multiple keys available. This sometimes occurs during key rollover.</remarks>
        public IssuerSigningKeyResolver IssuerSigningKeyResolver
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="IEnumerable{SecurityKey}"/> that are to be used for validating signed tokens. 
        /// </summary>
        public IEnumerable<SecurityKey> IssuerSigningKeys
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the issuer of the token. The delegate returns the issuer to use.
        /// </summary>
        public IssuerValidator IssuerValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the lifetime of the token
        /// </summary>
        public LifetimeValidator LifetimeValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="string"/> passed to <see cref="ClaimsIdentity(string, string, string)"/>. 
        /// </summary>
        /// <remarks>
        /// Controls the value <see cref="ClaimsIdentity.Name"/> returns. It will return the first <see cref="Claim.Value"/> where the <see cref="Claim.Type"/> equals <see cref="NameClaimType"/>.
        /// </remarks>
        public string NameClaimType
        {
            get
            {
                return _nameClaimType;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException(ErrorMessages.IDX10102);
                }

                _nameClaimType = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="string"/> passed to <see cref="ClaimsIdentity(string, string, string)"/>.
        /// </summary>
        /// <remarks>
        /// <para>Controls the <see cref="Claim"/>(s) returned from <see cref="ClaimsPrincipal.IsInRole( string )"/>.</para>
        /// <para>Each <see cref="Claim"/> returned will have a <see cref="Claim.Type"/> equal to <see cref="RoleClaimType"/>.</para>
        /// </remarks>
        public string RoleClaimType
        {
            get
            {
                return _roleClaimType;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentException(ErrorMessages.IDX10103);
                }

                _roleClaimType = value;
            }
        }

        /// <summary>
        /// Gets or sets a delegate that will be called to obtain the NameClaimType to use when creating a ClaimsIdentity
        /// when validating a token.
        /// </summary>
        public Func<SecurityToken, string, string> NameClaimTypeRetriever { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether tokens must have an 'expiration' value.
        /// </summary>
        [DefaultValue(true)]
        public bool RequireExpirationTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a <see cref="SecurityToken"/> can be valid if not signed.
        /// </summary>
        [DefaultValue(true)]
        public bool RequireSignedTokens { get; set; }

        /// <summary>
        /// Gets or sets a delegate that will be called to obtain the RoleClaimType to use when creating a ClaimsIdentity
        /// when validating a token.
        /// </summary>
        public Func<SecurityToken, string, string> RoleClaimTypeRetriever { get; set; }

        /// <summary>
        /// Gets or sets a boolean to control if the original token is saved when a session is created.       /// </summary>
        /// <remarks>The SecurityTokenValidator will use this value to save the orginal string that was validated.</remarks>
        [DefaultValue(false)]
        public bool SaveSigninToken
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or set the <see cref="ITokenReplayCache"/> that will be checked to help in detecting that a token has been 'seen' before.
        /// </summary>
        //public ITokenReplayCache TokenReplayCache
        //{
        //    get;
        //    set;
        //}

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="JwtSecurityToken.Actor"/> should be validated.
        /// </summary>
        [DefaultValue(false)]
        public bool ValidateActor
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a boolean to control if the audience will be validated during token validation.
        /// </summary>        
        [DefaultValue(true)]        
        public bool ValidateAudience
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a boolean to control if the issuer will be validated during token validation.
        /// </summary>                
        [DefaultValue(true)]
        public bool ValidateIssuer
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a boolean to control if the lifetime will be validated during token validation.
        /// </summary>                
        [DefaultValue(true)]
        public bool ValidateLifetime
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a boolean that controls if validation of the <see cref="SecurityKey"/> that signed the securityToken is called.
        /// </summary>
        [DefaultValue(false)]
        public bool ValidateIssuerSigningKey
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a string that represents a valid audience that will be used during token validation.
        /// </summary>
        public string ValidAudience
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="ICollection{String}"/> that contains valid audiences that will be used during token validation.
        /// </summary>
        public IEnumerable<string> ValidAudiences
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a <see cref="String"/> that represents a valid issuer that will be used during token validation.
        /// </summary>
        public string ValidIssuer
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="ICollection{String}"/> that contains valid issuers that will be used during token validation.
        /// </summary>
        public IEnumerable<string> ValidIssuers
        {
            get;
            set;
        }
    }
}
