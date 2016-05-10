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

using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Initializes a new instance of <see cref="SamlSecurityToken"/>.
    /// </summary>
    public class SamlSecurityToken : SecurityToken
    {
        /// <summary>
        /// Gets the Id of this <see cref="SamlSecurityToken"/>.
        /// </summary>
        public override string Id
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>.
        /// </summary>
        public override SecurityKey SecurityKey
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Get the time when this <see cref="SamlSecurityToken"/> was valid.
        /// </summary>
        public override DateTime ValidFrom
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Get the time when this <see cref="SamlSecurityToken"/> is no longer valid.
        /// </summary>
        public override DateTime ValidTo
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that signed this instance.
        /// </summary>
        /// <remarks><see cref="ISecurityTokenValidator"/>.ValidateToken(...) updates this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public override SecurityKey SigningKey
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the <see cref="SamlConditions"/>.
        /// </summary>
        public SamlConditions Conditions { get; set; }

        /// <summary>
        /// Gets the Issuer of this <see cref="SamlSecurityToken"/>.
        /// </summary>
        public override string Issuer
        {
            get
            {
                throw new NotImplementedException();
            }
        }
    }
}
