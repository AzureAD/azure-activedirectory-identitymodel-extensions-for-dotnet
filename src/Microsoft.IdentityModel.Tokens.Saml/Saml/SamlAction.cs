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
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Represents the Action element specified in [Saml, 2.4.5.1].
    /// </summary>
    public class SamlAction
    {
        private Uri _namespace;
        private string _value;

        /// <summary>
        /// Constructs an instance of <see cref="SamlAction"/> class.
        /// </summary>
        internal SamlAction() { }

        /// <summary>
        /// Constructs an instance of <see cref="SamlAction"/> class.
        /// </summary>
        /// <param name="value">Action value represented by this class.</param>
        public SamlAction(string value)
            : this(value, null)
        {
        }

        /// <summary>
        /// Constructs an instance of <see cref="SamlAction"/> class.
        /// </summary>
        /// <param name="value">Value represented by this class.</param>
        /// <param name="namespace">Namespace in which the action is interpreted.</param>
        public SamlAction(string value, Uri @namespace)
        {
            Value = value;
            Namespace = @namespace;
        }

        /// <summary>
        /// Gets or sets a URI reference representing the namespace in which the name of the
        /// specified action is to be interpreted. [Saml, 2.4.5.1]
        /// </summary>
        public Uri Namespace
        {
            get
            {
                return _namespace;
            }
            set
            {
                if (value == null)
                    throw LogArgumentNullException(nameof(value));

                if (!value.IsAbsoluteUri)
                    throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11502));

                _namespace = new Uri(SamlConstants.DefaultActionNamespace);
            }
        }

        /// <summary>
        /// Gets or sets the label for an action sought to be performed on the
        /// specified resource. [Saml, 2.4.5.1]
        /// </summary>
        public string Value
        {
            get
            {
                return _value;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogArgumentNullException(nameof(value));

                _value = value;
            }
        }
    }
}
