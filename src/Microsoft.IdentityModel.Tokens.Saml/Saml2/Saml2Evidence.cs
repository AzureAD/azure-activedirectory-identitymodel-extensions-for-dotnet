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
    /// Represents the Evidence element specified in [Saml2Core, 2.7.4.3].
    /// </summary>
    /// <remarks>
    /// Contains one or more assertions or assertion references that the SAML
    /// authority relied on in issuing the authorization decision. 
    /// [Saml2Core, 2.7.4.3]
    /// </remarks>
    public class Saml2Evidence
    {
        private Collection<Saml2Id> _assertionIdReferences = new Collection<Saml2Id>();
        private Collection<Saml2Assertion> _assertions = new Collection<Saml2Assertion>();
        private AbsoluteUriCollection _assertionUriReferences = new AbsoluteUriCollection();

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2Evidence"/> class.
        /// </summary>
        public Saml2Evidence()
        {}

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2Evidence"/> class from a <see cref="Saml2Assertion"/>.
        /// </summary>
        /// <param name="assertion"><see cref="Saml2Assertion"/> containing the evidence.</param>
        public Saml2Evidence(Saml2Assertion assertion)
        {
            if (null == assertion)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            this._assertions.Add(assertion);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2Evidence"/> class from a <see cref="Saml2Id"/>.
        /// </summary>
        /// <param name="idReference"><see cref="Saml2Id"/> containing the evidence.</param>
        public Saml2Evidence(Saml2Id idReference)
        {
            if (null == idReference)
                throw LogHelper.LogArgumentNullException(nameof(idReference));

            this._assertionIdReferences.Add(idReference);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Saml2Evidence"/> class from a <see cref="Uri"/>.
        /// </summary>
        /// <param name="uriReference"><see cref="Uri"/> containing the evidence.</param>
        public Saml2Evidence(Uri uriReference)
        {
            if (null == uriReference)
                throw LogHelper.LogArgumentNullException(nameof(uriReference));

            this._assertionUriReferences.Add(uriReference);
        }

        /// <summary>
        /// Gets a collection of <see cref="Saml2Id"/> for use by the <see cref="Saml2Evidence"/>.
        /// </summary>
        public Collection<Saml2Id> AssertionIdReferences
        {
            get { return this._assertionIdReferences; }
        }

        /// <summary>
        /// Gets a collection of <see cref="Saml2Assertion"/>  for use by the <see cref="Saml2Evidence"/>.
        /// </summary>
        public Collection<Saml2Assertion> Assertions
        {
            get { return this._assertions; }
        }

        /// <summary>
        /// Gets a collection of <see cref="Uri"/>  for use by the <see cref="Saml2Evidence"/>.
        /// </summary>
        public Collection<Uri> AssertionUriReferences
        {
            get { return this._assertionUriReferences; }
        }
    }
}
