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

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Represents the contents of SecurityTokenReference element.
    /// This type is used to identity a reference to a specific SecurityToken.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public class SecurityTokenReference
    {
        private string _id;
        private string _tokenType;
        private string _usage;
        private KeyIdentifier _keyIdentifier;

        internal SecurityTokenReference()
        {
        }

        /// <summary>
        /// Instantiates a <see cref="SecurityTokenReference"/> specifying the <see cref="KeyIdentifier"/>.
        /// </summary>
        /// <param name="keyIdentifier">the value of this <see cref="KeyIdentifier"/>.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="keyIdentifier"/> is null.</exception>
        public SecurityTokenReference(KeyIdentifier keyIdentifier)
        {
            KeyIdentifier = keyIdentifier;
        }

        /// <summary>
        /// Gets or sets the Id.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string Id
        {
            get => _id;
            set => _id = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the <see cref="KeyIdentifier"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null.</exception>
        public KeyIdentifier KeyIdentifier
        {
            get => _keyIdentifier;
            set => _keyIdentifier = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the TokenType.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string TokenType
        {
            get => _tokenType;
            set => _tokenType = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the Usage.
        /// </summary>
        /// <exception cref="ArgumentNullException">thrown if value is null or empty.</exception>
        public string Usage
        {
            get => _usage;
            set => _usage = !string.IsNullOrEmpty(value) ? value : throw LogHelper.LogArgumentNullException(nameof(value));
        }
    }
}
