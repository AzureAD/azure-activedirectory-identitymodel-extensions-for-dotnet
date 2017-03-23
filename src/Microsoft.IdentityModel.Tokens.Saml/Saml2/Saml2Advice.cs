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

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Advice element specified in [Saml2Core, 2.6.1].
    /// </summary>
    /// <remarks>
    /// This information MAY be ignored by applications without affecting either
    /// the semantics or the validity of the assertion. [Saml2Core, 2.6.1]
    /// </remarks>
    public class Saml2Advice
    {
        private Collection<Saml2Id> _assertionIdReferences = new Collection<Saml2Id>();
        private Collection<Saml2Assertion> _assertions = new Collection<Saml2Assertion>();
        private AbsoluteUriCollection _assertionUriReferences = new AbsoluteUriCollection();

        /// <summary>
        /// Creates an instance of Saml2Advice.
        /// </summary>
        public Saml2Advice()
        {
        }

        /// <summary>
        /// Gets a collection of <see cref="Saml2Id"/> representating the assertions in the <see cref="Saml2Advice"/>.
        /// </summary>
        public Collection<Saml2Id> AssertionIdReferences
        {
            get { return _assertionIdReferences; }
        }

        /// <summary>
        /// Gets a collection of <see cref="Saml2Assertion"/> representating the assertions in the <see cref="Saml2Advice"/>.
        /// </summary>
        public Collection<Saml2Assertion> Assertions
        {
            get { return _assertions; }
        }

        /// <summary>
        /// Gets a collection of <see cref="Uri"/> representing the assertions in the <see cref="Saml2Advice"/>.
        /// </summary>
        public Collection<Uri> AssertionUriReferences
        {
            get { return _assertionUriReferences; }
        }
    }
}