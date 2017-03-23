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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A SecurityKeyIdentifierClause for referencing SAML2-based security tokens.
    /// </summary>
    public class Saml2AssertionKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        /// <summary>
        /// Creates a Saml2AssertionKeyIdentifierClause for a given id.
        /// </summary>
        /// <param name="id">The id defining the clause to create.</param>
        public Saml2AssertionKeyIdentifierClause(string id)
            : this(id, null, 0)
        {
        }

        /// <summary>
        /// Creates a Saml2AssertionKeyIdentifierClause for a given id.
        /// </summary>
        /// <param name="id">The id defining the clause to create.</param>
        /// <param name="derivationNonce">
        /// An array of System.Byte that contains the nonce that was used to create a
        /// derived key. Sets the value that is returned by the System.IdentityModel.Tokens.SecurityKeyIdentifierClause.GetDerivationNonce()
        /// method.
        /// </param>
        /// <param name="derivationLength">The size of the derived key. Sets the value of the System.IdentityModel.Tokens.SecurityKeyIdentifierClause.DerivationLength
        /// property.
        /// </param>
        public Saml2AssertionKeyIdentifierClause(string id, byte[] derivationNonce, int derivationLength)
            : base(null, derivationNonce, derivationLength)
        {
            if (string.IsNullOrEmpty(id))
                throw LogHelper.LogArgumentNullException(nameof(id));

            Id = id;
        }

        /// <summary>
        /// Indicates whether the <see cref="SecurityKeyIdentifierClause"/> for an assertion matches the specified <see cref="SecurityKeyIdentifierClause"/>.
        /// </summary>
        /// <param name="assertionId">Id of the assertion</param>
        /// <param name="keyIdentifierClause">A <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>'True' if the keyIdentifier matches this. 'False' otherwise.</returns>
        public static bool Matches(string assertionId, SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (string.IsNullOrEmpty(assertionId))
                throw LogHelper.LogArgumentNullException(nameof(assertionId));

            if (null == keyIdentifierClause)
                return false;

            // Prefer our own type
            Saml2AssertionKeyIdentifierClause saml2Clause = keyIdentifierClause as Saml2AssertionKeyIdentifierClause;
            if (null != saml2Clause && StringComparer.Ordinal.Equals(assertionId, saml2Clause.Id))
                return true;

            // TODO - does this matter?
            //// For compatibility, match against the old WCF type.
            //// WCF will read SAML2-based key identifier clauses if our 
            //// SecurityTokenSerializer doesn't get the chance. Unfortunately,
            //// the TokenTypeUri and ValueType properties are internal, so
            //// we can't check if they're for SAML2 or not. We're just going
            //// to go with the fact that SAML Assertion IDs, in both versions,
            //// are supposed to be sufficiently random as to not intersect. 
            //// So, if the AssertionID matches our Id, we'll say that's good 
            //// enough.
            //Saml2AssertionKeyIdentifierClause wcfClause = keyIdentifierClause as Saml2AssertionKeyIdentifierClause;
            //if (null != wcfClause && StringComparer.Ordinal.Equals(assertionId, wcfClause.Id))
            //    return true;

            // Out of options.
            return false;
        }

        /// <summary>
        /// Indicates whether the <see cref="SecurityKeyIdentifierClause"/> for this instance is matches the specified <see cref="SecurityKeyIdentifierClause"/>.
        /// </summary>
        /// <param name="keyIdentifierClause">A <see cref="SecurityKeyIdentifierClause"/> to match.</param>
        /// <returns>True if the keyIdentifier matches this. False otherwise.</returns>
        public override bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            return ReferenceEquals(this, keyIdentifierClause) || Matches(Id, keyIdentifierClause);
        }

        /// <summary>
        /// Returns a <see cref="String"/> that represents the current <see cref="Object"/>.
        /// </summary>
        /// <returns>The Id of this instance as a string.</returns>
        public override string ToString()
        {
            return "Saml2AssertionKeyIdentifierClause( Id = '" + Id + "' )";
        }
    }
}
