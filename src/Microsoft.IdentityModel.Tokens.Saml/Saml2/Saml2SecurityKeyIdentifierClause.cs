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

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// This class is used when a Saml2Assertion is received without a KeyInfo inside the signature element.
    /// The KeyInfo describes the key required to check the signature.  When the key is needed this clause 
    /// will be presented to the current SecurityTokenResolver. It will contain the 
    /// Saml2Assertion fully read which can be querried to determine the key required.
    /// </summary>
    public class Saml2SecurityKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        private Saml2Assertion _assertion;

        /// <summary>
        /// Creates an instance of <see cref="Saml2SecurityKeyIdentifierClause"/>
        /// </summary>
        /// <param name="assertion">The assertion can be queried to obtain information about 
        /// the issuer when resolving the key needed to check the signature.</param>
        public Saml2SecurityKeyIdentifierClause(Saml2Assertion assertion)
            : base(typeof(Saml2SecurityKeyIdentifierClause).ToString())
        {
            this._assertion = assertion;
        }

        /// <summary>
        /// Gets the <see cref="Saml2Assertion"/> that is currently associated with this instance.
        /// </summary>
        /// <remarks>The assertion returned may be null.</remarks>
        public Saml2Assertion Assertion
        {
            get { return this._assertion; }
        }
    }
}
