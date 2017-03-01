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
    /// Represents the Action element specified in [Saml2Core, 2.7.4.2].
    /// </summary>
    public class Saml2Action
    {
        private Uri _namespace;
        private string _value;

        /// <summary>
        /// Constructs an instance of Saml2Action class.
        /// </summary>
        /// <param name="value">Value represented by this class.</param>
        /// <param name="actionNamespace">Namespace in which the action is interpreted.</param>
        public Saml2Action(string value, Uri actionNamespace)
        {
            if (string.IsNullOrEmpty(value))
                throw LogHelper.LogArgumentNullException(nameof(value));

            // ==
            // There is a discrepency between the schema and the text of the 
            // specification as to whether the Namespace attribute is optional
            // or required. The schema specifies required.
            // ==
            // Per the SAML 2.0 errata the schema takes precedence over the text, 
            // and the namespace attribute is required. This is errata item E36.
            // ==
            // SAML 2.0 errata at the time of this implementation:
            // http://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0-cd-02.pdf
            // ==
            if (null == actionNamespace)
                throw LogHelper.LogArgumentNullException(nameof(actionNamespace));

            if (!actionNamespace.IsAbsoluteUri)
                throw LogHelper.LogArgumentNullException("nameof(actionNamespace), ID0013");

            this._namespace = actionNamespace;
            this._value = value;
        }

        /// <summary>
        /// Gets or sets a URI reference representing the namespace in which the name of the
        /// specified action is to be interpreted. [Saml2Core, 2.7.4.2]
        /// </summary>
        public Uri Namespace
        {
            get
            { 
                return this._namespace; 
            }

            set
            {
                // See note in constructor about why this is required.
                if (null == value)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                if (!value.IsAbsoluteUri)
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("value is not an AbsoluteUri"));

                this._namespace = value;
            }
        }

        /// <summary>
        /// Gets or sets the label for an action sought to be performed on the 
        /// specified resource. [Saml2Core, 2.7.4.2]
        /// </summary>
        public string Value
        {
            get
            { 
                return this._value; 
            }

            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                this._value = value;
            }
        }
    }
}
