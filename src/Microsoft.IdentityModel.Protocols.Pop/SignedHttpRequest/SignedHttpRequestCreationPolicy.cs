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
using ClaimTypes = Microsoft.IdentityModel.Protocols.Pop.PopConstants.SignedHttpRequest.ClaimTypes;

namespace Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest
{
    /// <summary>
    /// A delegate that will be called to create and add additional claim(s), if set.
    /// </summary>
    /// <param name="payload">A SignedHttpRequest payload.</param>
    /// <param name="signedHttpRequestCreationData">A structure for wrapping parameters needed for SignedHttpRequest creation.</param>
    public delegate void AdditionalClaimCreator(IDictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData);

    /// <summary>
    /// A delegate that will be called to create and add the nonce claim, overriding the default behavior.
    /// </summary>
    /// <param name="payload">A SignedHttpRequest payload.</param>
    /// <param name="signedHttpRequestCreationData">A structure for wrapping parameters needed for SignedHttpRequest creation.</param>
    public delegate void CustomNonceCreator(IDictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData);

    /// <summary>
    /// Defines a policy for creating signed http requests.
    /// </summary>
    public class SignedHttpRequestCreationPolicy
    {
        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Nonce"/> claim should be created and added or not.
        /// </summary>
        public bool CreateNonce { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Ts"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateTs { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.M"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateM { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.U"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateU { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.P"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks>
        public bool CreateP { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.Q"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateQ { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.H"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateH { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="ClaimTypes.B"/> claim should be created and added or not.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3</remarks> 
        public bool CreateB { get; set; } = false;

        /// <summary>
        /// Gets or sets the <see cref="AdditionalClaimCreator"/> delegate.
        /// </summary>
        public AdditionalClaimCreator AdditionalClaimCreator { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="CustomNonceCreator"/> delegate. 
        /// </summary>
        public CustomNonceCreator CustomNonceCreator { get; set; }

        /// <summary>
        /// Default value for the <see cref="TimeAdjustment"/>.
        /// </summary>
        public static readonly TimeSpan DefaultTimeAdjustment = TimeSpan.Zero;

        /// <summary>
        /// Gets or sets a time adjustment to apply when creating the timestamp ("ts") claim.
        /// </summary>
        /// <remarks>Allows for adjusting the local time so it matches a server time.</remarks>
        public TimeSpan TimeAdjustment { get; set; } = DefaultTimeAdjustment;
    }
}
