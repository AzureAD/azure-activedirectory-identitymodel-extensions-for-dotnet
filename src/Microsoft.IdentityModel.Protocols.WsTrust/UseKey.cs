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
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a UseKey element.
    /// <para>
    /// <see cref="UseKey"/> can be used to specify an existing key to use with a wstrust request.
    /// </para>
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class UseKey
    {
        private string _signatureId;

        /// <summary>
        /// Creates an instance of <see cref="UseKey"/>.
        /// </summary>
        /// <param name="securityTokenElement">A <see cref="SecurityTokenElement"/> that contains key material that will be sent to the token issuer that can be set as the proof key inside the token returned.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityTokenElement"/> is null.</exception>
        public UseKey(SecurityTokenElement securityTokenElement)
        {
            SecurityTokenElement = securityTokenElement ?? throw LogHelper.LogArgumentNullException(nameof(securityTokenElement));
        }

        /// <summary>
        /// Gets the <see cref="SecurityTokenElement"/>.
        /// </summary>
        public SecurityTokenElement SecurityTokenElement
        {
            get;
        }

        /// <summary>
        /// Gets or sets the SignatureId that identifies a element in a signed envelope that shows proof of using the <see cref="SecurityTokenReference"/> or <see cref="SecurityToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if SignatureId is null or empty.</exception>
        public string SignatureId
        {
            get => _signatureId;
            set => _signatureId = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(SignatureId)) : value;
        }
    }
}
