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

namespace Microsoft.IdentityModel.Protocols.PoP.SignedHttpRequest
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="tokenWithCnfClaim"></param>
    /// <param name="payload"></param>
    /// <param name="httpRequestData"></param>
    /// <param name="popTokenCreationPolicy"></param>
    public delegate void CustomClaimCreator(string tokenWithCnfClaim, IDictionary<string, object> payload, HttpRequestData httpRequestData, PopTokenCreationPolicy popTokenCreationPolicy);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="payload"></param>
    /// <param name="popTokenCreationPolicy"></param>
    public delegate void NonceClaimCreator(IDictionary<string, object> payload, PopTokenCreationPolicy popTokenCreationPolicy);

    /// <summary>
    /// 
    /// </summary>
    public class PopTokenCreationPolicy
    {
        /// <summary>
        /// </summary>
        public static readonly TimeSpan DefaultClockSkew = TimeSpan.Zero;

        /// <summary>
        /// 
        /// </summary>
        public TimeSpan ClockSkew { get; set; } = DefaultClockSkew;

        /// <summary>
        /// 
        /// </summary>
        public bool CreateNonce { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.Ts"/> claim should be created or not.
        /// </summary>
        public bool CreateTs { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.M"/> claim should be created or not.
        /// </summary>
        public bool CreateM { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.U"/> claim should be created or not.
        /// </summary>
        public bool CreateU { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.P"/> claim should be created or not.
        /// </summary>
        public bool CreateP { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.Q"/> claim should be created or not.
        /// </summary>
        public bool CreateQ { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.H"/> claim should be created or not.
        /// </summary>
        public bool CreateH { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.B"/> claim should be created or not.
        /// </summary>
        public bool CreateB { get; set; } = false;

        /// <summary>
        /// 
        /// </summary>
        public CustomClaimCreator CustomClaimCreator { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public NonceClaimCreator NonceClaimCreator { get; set; }
    }
}
