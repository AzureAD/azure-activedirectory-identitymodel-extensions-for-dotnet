// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.IdentityModel.Selectors;
    using System.Security.Claims;

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
            this.SaveBootstrapContext = false;
            this.ValidateIssuer = true;
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
        [DefaultValue(true)]
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
