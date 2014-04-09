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

using System.Collections.Generic;
using System.Security.Claims;
using System.Xml;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// ISecurityTokenValidator
    /// </summary>
    public interface ISecurityTokenValidator
    {
        /// <summary>
        /// Gets or sets the authentication type to use when creating the claims identity
        /// </summary>
        string AuthenticationType { get; set; }

        /// <summary>
        /// Answers the question if the token can be read, it is assumed if the token can be read, it can be validated.
        /// </summary>
        bool CanReadToken(string securityToken);

        /// <summary>
        /// Gets or sets the clock skew to apply when validating times
        /// </summary>
        Int32 ClockSkewInSeconds { get; set; }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        Int32 MaximumTokenSizeInBytes { get; set; }
        
        /// <summary>
        /// Validates a token passed as a string using <see cref="TokenValidationParameters"/>
        /// </summary>
        ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters);        
    }
}
