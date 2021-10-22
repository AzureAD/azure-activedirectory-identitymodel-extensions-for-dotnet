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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.IdentityModel.Validators
{
    /// <summary>
    /// Factory class for creating the AadIssuerValidator per authority.
    /// </summary>
    public class AadIssuerValidatorFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AadIssuerValidatorFactory"/> class.
        /// </summary>
        public AadIssuerValidatorFactory():this(null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AadIssuerValidatorFactory"/> class.
        /// </summary>
        /// <param name="httpClient">Optional HttpClient to use to retrieve the endpoint metadata (can be null).</param>
        public AadIssuerValidatorFactory(
            HttpClient httpClient = null)
        {
            HttpClient = httpClient;
        }

        private readonly IDictionary<string, AadIssuerValidator> _issuerValidators = new ConcurrentDictionary<string, AadIssuerValidator>();

        private HttpClient HttpClient { get; }

        /// <summary>
        /// Gets an <see cref="AadIssuerValidator"/> for an Azure Active Directory (AAD) authority.
        /// </summary>
        /// <param name="aadAuthority">The authority to create the validator for, e.g. https://login.microsoftonline.com/. </param>
        /// <returns>A <see cref="AadIssuerValidator"/> for the aadAuthority.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="aadAuthority"/> is null or empty.</exception>
        public AadIssuerValidator GetAadIssuerValidator(string aadAuthority)
        {
            if (string.IsNullOrEmpty(aadAuthority))
            {
                throw new ArgumentNullException(nameof(aadAuthority));
            }

            Uri.TryCreate(aadAuthority, UriKind.Absolute, out Uri authorityUri);
            string authorityHost = authorityUri?.Authority ?? new Uri(AadIssuerValidatorConstants.FallbackAuthority).Authority;

            if (_issuerValidators.TryGetValue(authorityHost, out AadIssuerValidator aadIssuerValidator))
            {
                return aadIssuerValidator;
            }

            _issuerValidators[authorityHost] = new AadIssuerValidator(
                HttpClient,
                aadAuthority);

            return _issuerValidators[authorityHost];
        }
    }
}
