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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the AudienceRestriction element specified in [Saml2Core, 2.5.1.4].
    /// </summary>
    /// <remarks>
    /// If the Audiences collection is empty, an InvalidOperationException will be 
    /// thrown during serialization.
    /// </remarks>
    public class Saml2AudienceRestriction
    {
        private Collection<string> _audiences = new Collection<string>();

        /// <summary>
        /// Creates an instance of Saml2AudienceRestriction.
        /// </summary>
        public Saml2AudienceRestriction()
        { }

        /// <summary>
        /// Creates an instance of Saml2AudienceRestriction.
        /// </summary>
        /// <param name="audience">The audience element contained in this restriction.</param>
        public Saml2AudienceRestriction(string audience)
            : this(new string[] { audience })
        { }

        /// <summary>
        /// Creates an instance of Saml2AudienceRestriction.
        /// </summary>
        /// <param name="audiences">The collection of audience elements contained in this restriction.</param>
        public Saml2AudienceRestriction(IEnumerable<string> audiences)
        {
            if (null == audiences)
                throw LogHelper.LogArgumentNullException(nameof(audiences));

            foreach (var audience in audiences)
            {
                if (null == audience)
                    throw LogHelper.LogArgumentNullException(nameof(audiences));

                _audiences.Add(audience);
            }
        }

        /// <summary>
        /// Gets the audiences for which the assertion is addressed.
        /// </summary>
        public ICollection<string> Audiences
        {
            get { return _audiences; }
        }
    }
}
