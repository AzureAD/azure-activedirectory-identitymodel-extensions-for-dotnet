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
    using System.ComponentModel;
    using System.IdentityModel.Selectors;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    public class TokenValidationParameters
    {
        /// <summary>
        /// The default maximum size of a token that the runtime will process.
        /// </summary>
        public static readonly Int32 DefaultMaximumTokenSizeInBytes = 2 * 1024 * 1024; // 2MB

        /// <summary>
        /// The default clock skew.
        /// </summary>
        public static readonly Int32 DefaultClockSkewInSeconds = 300;

        private Int32 _clockSkew;
        private Int32 _maximumTokenSizeInBytes;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParameters"/> class.
        /// </summary>        
        public TokenValidationParameters()
        {
            SaveSigninToken = false;
            ValidateAudience = true;
            ValidateIssuer = true;
            _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
            _clockSkew = TokenValidationParameters.DefaultClockSkewInSeconds;
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
        /// Gets or sets the <see cref="IEnumerable{SecurityKey}"/> that are to be used for validating signed tokens. 
        /// </summary>
        public IEnumerable<SecurityKey> IssuerSigningKeys
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the clock skew to apply when validatin times
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"> if value is less than 0.</exception>
        [DefaultValue(300)]
        public Int32 ClockSkewInSeconds
        {
            get
            {
                return _clockSkew;
            }

            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("ClockSkew", JwtErrors.Jwt10120);
                }

                _clockSkew = value;
            }
        }

        /// <summary>
        /// Gets or sets the maximum size for a token that the runtime will process.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">thrown if 'value' is less than 1.</exception>
        [DefaultValue(2087152)]
        public Int32 MaximumTokenSizeInBytes 
        {
            get 
            { 
                return _maximumTokenSizeInBytes; 
            }
            
            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException("MaximumTokenSizeInBytes", JwtErrors.Jwt10119 );
                }
                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Gets or sets a boolean to control if the original token is saved when a session is created.
        /// </summary>
        [DefaultValue(false)]
        public bool SaveSigninToken
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
        /// Gets or sets a <see cref="IEnumerable{String}"/> that contains valid audiences that will be used during token validation.
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
        /// Gets or sets a <see cref="IEnumerable{String}"/> that contains valid issuers that will be used during token validation.
        /// </summary>
        public IEnumerable<string> ValidIssuers
        {
            get;
            set;
        }
    }
}
