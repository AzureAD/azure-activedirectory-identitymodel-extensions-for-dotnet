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

namespace System.IdentityModel.Tokens
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel;

    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    public class TokenValidationParameters
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParameters"/> class.
        /// </summary>        
        public TokenValidationParameters()
        {
            SaveSigninToken = false;
            ValidateAudience = true;
            ValidateIssuer = true;
            ValidateActor = false;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the audience of the token
        /// </summary>
        public Func<string, SecurityToken, bool> AudienceValidator
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
        public Func<string, IEnumerable<SecurityKey>> IssuerSigningKeyRetriever
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
        /// Gets or sets the <see cref="SecurityToken"/> that is used for validating signed tokens. 
        /// </summary>
        public SecurityToken IssuerSigningToken
        {
            get;
            set;
        }

        // TODO - remove this method.
        /// <summary>
        /// Gets or sets the <see cref="IEnumerable{SecurityToken}"/> that are to be used for validating signed tokens. 
        /// </summary>
        public IEnumerable<SecurityToken> IssuerSigningTokens
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the issuer of the token
        /// </summary>
        public Func<string, SecurityToken, bool> IssuerValidator
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a delegate that will be used to validate the lifetime of the token
        /// </summary>
        public Func<string, SecurityToken, bool> LifetimeValidator
        {
            get;
            set;
        }

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
