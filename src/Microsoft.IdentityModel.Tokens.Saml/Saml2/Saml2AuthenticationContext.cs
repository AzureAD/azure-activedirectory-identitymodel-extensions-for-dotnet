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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the AuthnContext element specified in [Saml2Core, 2.7.2.2].
    /// </summary>
    /// <remarks>
    /// <para>
    /// This base class does not directly support any by-value authentication 
    /// context declarations (represented in XML by the AuthnContextDecl element). 
    /// To support by-value declarations, extend this class to support the data 
    /// model and extend Saml2AssertionSerializer, overriding ReadAuthnContext 
    /// and WriteAuthnContext to read and write the by-value declaration.
    /// </para>
    /// </remarks>
    public class Saml2AuthenticationContext
    {
        private Collection<Uri> _authenticatingAuthorities = new Collection<Uri>();
        private Uri _classReference;
        private Uri _declarationReference;

        /// <summary>
        /// Creates an instance of Saml2AuthenticationContext.
        /// </summary>
        public Saml2AuthenticationContext()
            : this(null, null)
        {
        }

        /// <summary>
        /// Creates an instance of Saml2AuthenticationContext.
        /// </summary>
        /// <param name="classReference">The class reference of the authentication context.</param>
        public Saml2AuthenticationContext(Uri classReference)
            : this(classReference, null)
        {
        }

        /// <summary>
        /// Creates an instance of Saml2AuthenticationContext.
        /// </summary>
        /// <param name="classReference">The class reference of the authentication context.</param>
        /// <param name="declarationReference">The declaration reference of the authentication context.</param>
        public Saml2AuthenticationContext(Uri classReference, Uri declarationReference)
        {
            if (null != classReference && !classReference.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(
                    new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(classReference), classReference)));

            if (null != declarationReference && !declarationReference.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(
                    new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(declarationReference), declarationReference)));

            _classReference = classReference;
            _declarationReference = declarationReference;
        }

        /// <summary>
        /// Gets Zero or more unique identifiers of authentication authorities that 
        /// were involved in the authentication of the principal (not including
        /// the assertion issuer, who is presumed to have been involved without
        /// being explicitly named here). [Saml2Core, 2.7.2.2]
        /// </summary>
        public ICollection<Uri> AuthenticatingAuthorities
        {
            get { return _authenticatingAuthorities; }
        }

        /// <summary>
        /// Gets or sets a URI reference identifying an authentication context class that 
        /// describes the authentication context declaration that follows.
        /// [Saml2Core, 2.7.2.2]
        /// </summary>
        public Uri ClassReference
        {
            get { return _classReference; }
            set
            {
                if (null != value && !value.IsAbsoluteUri)
                    throw LogHelper.LogExceptionMessage(
                        new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(value), value)));

                _classReference = value;
            }
        }

        /// <summary>
        /// Gets or sets a URI reference that identifies an authentication context 
        /// declaration. [Saml2Core, 2.7.2.2]
        /// </summary>
        public Uri DeclarationReference
        {
            get { return _declarationReference; }
            set
            {
                if (null != value && !value.IsAbsoluteUri)
                    throw LogHelper.LogExceptionMessage(
                        new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(value), value)));

                _declarationReference = value;
            }
        }
    }
}
