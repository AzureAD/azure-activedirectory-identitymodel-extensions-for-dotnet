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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Conditions element specified in [Saml2Core, 2.5.1].
    /// </summary>
    public class Saml2Conditions
    {
        private Collection<Saml2AudienceRestriction> _audienceRestrictions = new Collection<Saml2AudienceRestriction>();
        private DateTime? _notBefore;
        private DateTime? _notOnOrAfter;

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2Conditions"/>. class.
        /// </summary>
        public Saml2Conditions()
        { }

        /// <summary>
        /// Gets a collection of <see cref="Saml2AudienceRestriction"/> that the assertion is addressed to.
        /// [Saml2Core, 2.5.1]
        /// </summary>
        public Collection<Saml2AudienceRestriction> AudienceRestrictions
        {
            get { return _audienceRestrictions; }
        }

        /// <summary>
        /// Gets or sets the earliest time instant at which the assertion is valid.
        /// [Saml2Core, 2.5.1]
        /// </summary>
        public DateTime? NotBefore
        {
            get { return _notBefore; }
            set
            {
                value = DateTimeUtil.ToUniversalTime(value);

                // NotBefore must be earlier than NotOnOrAfter
                if (null != value && null != _notOnOrAfter)
                {
                    if (value.Value >= _notOnOrAfter.Value)
                        throw LogHelper.LogArgumentNullException("nameof(value), ID4116");
                }

                _notBefore = value;
            }
        }

        /// <summary>
        /// Gets or sets the time instant at which the assertion has expired.
        /// [Saml2Core, 2.5.1]
        /// </summary>
        public DateTime? NotOnOrAfter
        {
            get { return _notOnOrAfter; }
            set
            {
                value = DateTimeUtil.ToUniversalTime(value);

                // NotBefore must be earlier than NotOnOrAfter
                if (null != value && null != _notBefore)
                {
                    if (value.Value <= _notBefore.Value)
                        throw LogHelper.LogArgumentNullException("nameof(value), ID4116");
                }

                _notOnOrAfter = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the assertion SHOULD be used immediately and MUST NOT
        /// be retained for future use. [Saml2Core, 2.5.1]
        /// </summary>
        public bool OneTimeUse
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2ProxyRestriction"/> that specified limitations that the asserting party imposes on relying parties
        /// that wish to subsequently act as asserting parties themselves and issue assertions of their own on the basis of the information contained in
        /// the original assertion. [Saml2Core, 2.5.1]
        /// </summary>
        public Saml2ProxyRestriction ProxyRestriction
        {
            get; set;
        }
    }
}
