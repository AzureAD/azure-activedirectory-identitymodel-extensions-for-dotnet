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

namespace System.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Initializes a new instance of <see cref="Saml2Conditions"/>. 
    /// </summary>
    public class Saml2Conditions
    {
        /// <summary>
        /// Gets or sets the notbefore time.
        /// </summary>
        public DateTime? NotBefore
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the expires time.
        /// </summary>
        public DateTime? Expires
        {
            get; set;
        }

        /// <summary>
        /// Gets of sets the list of Saml2AudienceRestriction.
        /// </summary>
        public IList<Saml2AudienceRestriction> AudienceRestrictions { get; set; }
    }
}
