//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Contains a set of parameters that are used by <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    public class TokenValidationParameters
    {
        /// <summary>
        /// Creates a new <see cref="TokenValidationParameters"/> with <see cref="AudienceUriMode"/> = BearerKeyOnly and <see cref="SaveBootstrapContext"/> = false.
        /// </summary>
        /// 
        public TokenValidationParameters()
        {
            AudienceUriMode = AudienceUriMode.BearerKeyOnly;
            SaveBootstrapContext = false;
            ValidateIssuer = true;
        }

        /// <summary>
        /// Gets or sets an audience that is considered valid.
        /// </summary>
        public string AllowedAudience 
        { 
            get; 
            set; 
        }

        /// <summary>
        /// Gets or sets a collection of audiences that are considered valid.
        /// </summary>
        public IEnumerable<string> AllowedAudiences 
        { 
            get; 
            set; 
        }

        /// <summary>
        /// Gets or sets the <see cref="AudienceUriMode"/> to use when validating audience values.
        /// </summary>
        [DefaultValue(AudienceUriMode.BearerKeyOnly)]
        public AudienceUriMode AudienceUriMode
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a value indicating whether <see cref="JwtSecurityToken"/> should be attached to <see cref="ClaimsIdentity.BootstrapContext"/> during validation.
        /// </summary>
        [DefaultValue(false)]
        public bool SaveBootstrapContext
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a <see cref="SecurityToken"/> to use when validating signatures.
        /// </summary>
        public SecurityToken SigningToken 
        { 
            get; 
            set; 
        }

        /// <summary>
        /// Gets or sets a collection of <see cref="SecurityToken"/> to use when validating signatures.
        /// </summary>
        public IEnumerable<SecurityToken> SigningTokens
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="JwtSecurityToken.Issuer"/> should be validated.
        /// </summary>
        /// <remarks>The <see cref="JwtSecurityToken"/> must have an Issuer that is other than whitespace.</remarks>
        [DefaultValue( true )]
        public bool ValidateIssuer
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets an issuer that is considered valid.
        /// </summary>
        public string ValidIssuer 
        { 
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a collection of issuers that is considered valid.
        /// </summary>
        public IEnumerable<string> ValidIssuers 
        { 
            get; 
            set; 
        }
    }
}
