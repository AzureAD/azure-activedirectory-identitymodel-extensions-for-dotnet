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
using System.Security.Claims;
using static System.String;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Saml2
{
    // TODO do we need this class?
    /// <summary>
    /// This class is used to specify the context of the authorization event.
    /// </summary>
    public class AuthorizationContext
    {
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
            Principal = principal ?? throw LogArgumentNullException(nameof(principal));

            if (IsNullOrEmpty(resource))
                throw LogArgumentNullException(nameof(resource));

            Resource.Add(new Claim(ClaimTypes.Name, resource));

            if (!IsNullOrEmpty(action))
                Action.Add(new Claim(ClaimTypes.Name, action));
        }

        /// <summary>
        /// Creates an AuthorizationContext with the specified principal, resource, and action.
        /// </summary>
        /// <param name="principal">The principal to check authorization for</param>
        /// <param name="resource">The resource for checking authorization to</param>
        /// <param name="action">The action to be performed on the resource</param>
        /// <exception cref="ArgumentNullException">When <paramref name="principal"/> or <paramref name="resource"/> or <paramref name="action"/> is null</exception>
        public AuthorizationContext(ClaimsPrincipal principal, ICollection<Claim> resource, ICollection<Claim> action)
        {
            Principal = principal ?? throw LogArgumentNullException(nameof(principal));
            Resource = resource ?? throw LogArgumentNullException(nameof(resource));
            Action = action ?? throw LogArgumentNullException(nameof(action));
        }

        /// <summary>
        /// Gets the authorization action
        /// </summary>
        public ICollection<Claim> Action
        {
            get;
        }

        /// <summary>
        /// Gets the authorization resource
        /// </summary>
        public ICollection<Claim> Resource
        {
            get;
        }

        /// <summary>
        /// Gets the authorization principal
        /// </summary>
        public ClaimsPrincipal Principal
        {
            get;
        }
    }
}
