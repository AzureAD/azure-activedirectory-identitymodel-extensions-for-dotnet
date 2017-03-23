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
    /// Represents the SubjectConfirmation element specified in [Saml2Core, 2.4.1.1]. 
    /// </summary>
    public class Saml2SubjectConfirmation
    {
        private Saml2SubjectConfirmationData _data;
        private Uri _method;
        private Saml2NameIdentifier _nameId;

        /// <summary>
        /// Initializes an instance of <see cref="Saml2SubjectConfirmation"/> from a <see cref="Uri"/> indicating the
        /// method of confirmation.
        /// </summary>
        /// <param name="method">The <see cref="Uri"/> to use for initialization.</param>
        public Saml2SubjectConfirmation(Uri method)
            : this(method, null)
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="Saml2SubjectConfirmation"/> from a <see cref="Uri"/> indicating the
        /// method of confirmation and <see cref="Saml2SubjectConfirmationData"/>.
        /// </summary>
        /// <param name="method">The <see cref="Uri"/> to use for initialization.</param>
        /// <param name="data">The <see cref="Saml2SubjectConfirmationData"/> to use for initialization.</param>
        public Saml2SubjectConfirmation(Uri method, Saml2SubjectConfirmationData data)
        {
            if (null == method)
                throw LogHelper.LogArgumentNullException(nameof(method));

            if (!method.IsAbsoluteUri)
                throw LogHelper.LogArgumentNullException("nameof(method), ID0013");

            _method = method;
            _data = data;
        }

        /// <summary>
        /// Gets or sets a URI reference that identifies a protocol or mechanism to be used to 
        /// confirm the subject. [Saml2Core, 2.4.1.1]
        /// </summary>
        public Uri Method
        {
            get
            {
                return _method;
            }
            set
            {
                if (null == value)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                if (!value.IsAbsoluteUri)
                    throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("ID0013"));

                _method = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2NameIdentifier"/> expected to satisfy the enclosing subject 
        /// confirmation requirements. [Saml2Core, 2.4.1.1]
        /// </summary>
        public Saml2NameIdentifier NameIdentifier
        {
            get { return _nameId; }
            set { _nameId = value; }
        }

        /// <summary>
        /// Gets or sets additional <see cref="Saml2SubjectConfirmationData"/> to be used by a specific confirmation
        /// method. [Saml2Core, 2.4.1.1]
        /// </summary>
        public Saml2SubjectConfirmationData SubjectConfirmationData
        {
            get { return _data; }
            set { _data = value; }
        }
    }
}