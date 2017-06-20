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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the AttributeStatement element specified in [Saml2Core, 2.7.3].
    /// </summary>
    public class Saml2AttributeStatement : Saml2Statement
    {
        /// <summary>
        /// Creates an instance of Saml2AttributeStatement.
        /// </summary>
        public Saml2AttributeStatement()
        {
            Attributes = new List<Saml2Attribute>();
        }

        /// <summary>
        /// Creates an instance of Saml2AttributeStatement.
        /// </summary>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> contained in this statement.</param>
        public Saml2AttributeStatement(Saml2Attribute attribute)
            : this(new Saml2Attribute[] { attribute })
        { }

        /// <summary>
        /// Creates an instance of Saml2AttributeStatement.
        /// </summary>
        /// <param name="attributes">The collection of <see cref="Saml2Attribute"/> elements contained in this statement.</param>
        public Saml2AttributeStatement(IEnumerable<Saml2Attribute> attributes)
        {
            if (attributes == null)
                throw LogArgumentNullException(nameof(attributes));

            Attributes = new List<Saml2Attribute>(attributes);
        }

        /// <summary>
        /// Gets the collection of <see cref="Saml2Attribute"/> of this statement. [Saml2Core, 2.7.3]
        /// </summary>
        public ICollection<Saml2Attribute> Attributes
        {
            get;
        }
    }
}
