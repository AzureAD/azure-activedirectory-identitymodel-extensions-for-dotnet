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
    /// Represents the AuthzDecisionStatement specified in [Saml2Core, 2.7.4].
    /// </summary>
    public class Saml2AuthorizationDecisionStatement : Saml2Statement
    {
        /// <summary>
        /// The empty URI reference, which may be used with the meaning 
        /// "the start of the current document" for the Resource property.
        /// </summary>
        public static readonly Uri EmptyResource = new Uri(string.Empty, UriKind.Relative);

        private Collection<Saml2Action> _actions = new Collection<Saml2Action>();
        private string _decision;
        private Uri _resource;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2AuthorizationDecisionStatement"/> class from
        /// a resource and decision.
        /// </summary>
        /// <param name="resource">The <see cref="Uri"/> of the resource to be authorized.</param>
        /// <param name="decision">The AccessDecision in use.</param>
        public Saml2AuthorizationDecisionStatement(Uri resource, string decision)
            : this(resource, decision, null)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2AuthorizationDecisionStatement"/> class from
        /// a resource and decision.
        /// </summary>
        /// <param name="resource">The <see cref="Uri"/> of the resource to be authorized.</param>
        /// <param name="decision">The AccessDecision in use.</param>
        /// <param name="actions">Collection of <see cref="Saml2Action"/> specifications.</param>
        public Saml2AuthorizationDecisionStatement(Uri resource, string decision, IEnumerable<Saml2Action> actions)
        {
            if (resource == null)
                throw LogHelper.LogArgumentNullException(nameof(resource));

            if (string.IsNullOrEmpty(decision))
                throw LogHelper.LogArgumentNullException(nameof(decision));

            // This check is making sure the resource is either a well-formed absolute uri or
            // an empty relative uri before passing through to the rest of the constructor.
            if (!(resource.IsAbsoluteUri || resource.Equals(EmptyResource)))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(resource), resource.OriginalString)));

            _resource = resource;
            _decision = decision;

            if (null != actions)
            {
                foreach (Saml2Action action in actions)
                {
                    _actions.Add(action);
                }
            }
        }

        /// <summary>
        /// Gets of set the set of <see cref="Saml2Action"/> authorized to be performed on the specified
        /// resource. [Saml2Core, 2.7.4]
        /// </summary>
        public Collection<Saml2Action> Actions
        {
            get { return _actions; }
        }

        /// <summary>
        /// Gets or sets the AccessDecision rendered by the SAML authority with respect to the specified resource. [Saml2Core, 2.7.4]
        /// </summary>
        public string Decision
        {
            get { return _decision; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _decision = value;
            }
        }

        /// <summary>
        /// Gets or sets a set of <see cref="Saml2Evidence"/> that the SAML authority relied on in making 
        /// the decision. [Saml2Core, 2.7.4]
        /// </summary>
        public Saml2Evidence Evidence
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets a URI reference identifying the resource to which access 
        /// authorization is sought. [Saml2Core, 2.7.4]
        /// </summary>
        /// <remarks>
        /// In addition to any absolute URI, the Resource may also be the 
        /// empty URI reference, and the meaning is defined to be "the start
        /// of the current document". [Saml2Core, 2.7.4]
        /// </remarks>
        public Uri Resource
        {
            get { return _resource; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                if (!(value.IsAbsoluteUri || value.Equals(EmptyResource)))
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX11134, nameof(value), value.OriginalString)));

                _resource = value;
            }
        }
    }
}
