//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Logging;
using System;
using System.ComponentModel;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines properties shared across all security token handlers.
    /// </summary>
    public abstract class TokenHandler
    {
        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
        private int _maximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, 
        /// then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;

        /// <summary>
        /// Gets and sets the maximum token size in bytes that will be processed.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public virtual int MaximumTokenSizeInBytes
        {
            get => _maximumTokenSizeInBytes; 
            set => _maximumTokenSizeInBytes =  (value < 1) ? throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), FormatInvariant(LogMessages.IDX10101, value))) : value;
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="TokenLifetimeInMinutes"/> for configuration.</remarks>
        [DefaultValue(true)]
        public bool SetDefaultTimesOnTokenCreation { get; set; } = true;

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used during token creation to set the default expiration ('exp'). </remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get => _defaultTokenLifetimeInMinutes;
            set => _defaultTokenLifetimeInMinutes = (value < 1) ? throw LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), FormatInvariant(LogMessages.IDX10104, value))) : value;
        }
    }
}
