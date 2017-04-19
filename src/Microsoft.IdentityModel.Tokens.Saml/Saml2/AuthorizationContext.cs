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

using System.Collections.ObjectModel;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Saml2
{
    /// <summary>
    /// This class is used to specify the context of the authorization event.
    /// </summary>
    public class AuthorizationContext
    {
        Collection<System.Security.Claims.Claim> _action = new Collection<System.Security.Claims.Claim>();
        Collection<System.Security.Claims.Claim> _resource = new Collection<System.Security.Claims.Claim>();
        ClaimsPrincipal _principal;

        /// <summary>
        /// Creates an AuthorizationContext with the specified principal, resource, and action.
        /// </summary>
        /// <param name="principal">The principal to be authorized.</param>
        /// <param name="resource">The resource to be authorized for.</param>
        /// <param name="action">The action to be performed on the resource.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="principal"/> or <paramref name="resource"/> is set to null.
        /// </exception>
        public AuthorizationContext(ClaimsPrincipal principal, string resource, string action)
        {
            if (principal == null)
                throw LogHelper.LogArgumentNullException(nameof(principal));

            if (string.IsNullOrEmpty(resource))
                throw LogHelper.LogArgumentNullException(nameof(resource));

            _principal = principal;
            _resource.Add(new System.Security.Claims.Claim(ClaimTypes.Name, resource));
            if (action != null)
            {
                _action.Add(new System.Security.Claims.Claim(ClaimTypes.Name, action));
            }
        }

        /// <summary>
        /// Creates an AuthorizationContext with the specified principal, resource, and action.
        /// </summary>
        /// <param name="principal">The principal to check authorization for</param>
        /// <param name="resource">The resource for checking authorization to</param>
        /// <param name="action">The action to be performed on the resource</param>
        /// <exception cref="ArgumentNullException">When <paramref name="principal"/> or <paramref name="resource"/> or <paramref name="action"/> is null</exception>
        public AuthorizationContext(ClaimsPrincipal principal, Collection<System.Security.Claims.Claim> resource, Collection<System.Security.Claims.Claim> action)
        {
            if (principal == null)
                throw LogHelper.LogArgumentNullException(nameof(principal));

            if (resource == null)
                throw LogHelper.LogArgumentNullException(nameof(resource));

            if (action == null)
                throw LogHelper.LogArgumentNullException(nameof(action));

            _principal = principal;
            _resource = resource;
            _action = action;
        }

        /// <summary>
        /// Gets the authorization action
        /// </summary>
        public Collection<System.Security.Claims.Claim> Action
        {
            get { return _action; }
        }

        /// <summary>
        /// Gets the authorization resource
        /// </summary>
        public Collection<System.Security.Claims.Claim> Resource
        {
            get { return _resource; }
        }

        /// <summary>
        /// Gets the authorization principal
        /// </summary>
        public ClaimsPrincipal Principal
        {
            get { return _principal; }
        }
    }
}
