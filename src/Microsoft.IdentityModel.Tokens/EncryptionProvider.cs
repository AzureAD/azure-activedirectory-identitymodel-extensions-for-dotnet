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

namespace Microsoft.IdentityModel.Tokens
{
    public abstract class EncryptionProvider : IEncryptingProvider, IDecryptingProvider, IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionProvider"/> class used to encode and decode Ciphertext and Authentication Tag.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for encrypting the plaintext.</param>
        /// <param name="iv">The initialization vector that will be used for encrypting the plaintext. </param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        protected EncryptionProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));
            
            Key = key;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets or sets a user context for a <see cref="EncryptionProvider"/>.
        /// </summary>
        public string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>.
        /// </summary>
        public SecurityKey Key { get; private set; }

        public string Algorithm { get; private set; }

        #region IDisposable Members

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Can be over written in descendants to dispose of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>     
        protected abstract void Dispose(bool disposing);

        #endregion
    }
}
