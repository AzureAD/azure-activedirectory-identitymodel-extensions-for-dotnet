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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The Entropy used in both token request message and token response message. 
    /// </summary>
    public class Entropy : ProtectedKey
    {
        /// <summary>
        /// 
        /// </summary>
        internal Entropy()
        { }

        /// <summary>
        /// Constructor for sending entropy in binary secret format.
        /// </summary>
        /// <param name="secret">The key material.</param>
        public Entropy( byte[] secret )
            : base( secret )
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="binarySecret"></param>
        public Entropy(BinarySecret binarySecret)
        {
            BinarySecret = binarySecret;
        }

        /// <summary>
        /// 
        /// </summary>
        public BinarySecret BinarySecret { get; internal set; }

        /// <summary>
        /// Constructor for sending entropy in encrypted key format.
        /// </summary>
        /// <param name="secret">The key material.</param>
        /// <param name="wrappingCredentials">The encrypting credentials used to encrypt the key material.</param>
        public Entropy( byte[] secret, EncryptingCredentials wrappingCredentials )
            : base( secret, wrappingCredentials )
        {
        }

        /// <summary>
        /// Constructs an entropy instance with the protected key.
        /// </summary>
        /// <param name="protectedKey">The protected key which can be either binary secret or encrypted key.</param>
        public Entropy( ProtectedKey protectedKey )
            : base( GetKeyBytesFromProtectedKey( protectedKey ), GetWrappingCredentialsFromProtectedKey( protectedKey ) )
        {
        }

        static byte[] GetKeyBytesFromProtectedKey( ProtectedKey protectedKey )
        {
            if (protectedKey == null)
                LogHelper.LogArgumentNullException(nameof(protectedKey));

            return protectedKey.Secret;
        }

        static EncryptingCredentials GetWrappingCredentialsFromProtectedKey( ProtectedKey protectedKey )
        {
            if (protectedKey == null)
                LogHelper.LogArgumentNullException(nameof(protectedKey));

            return protectedKey.WrappingCredentials;
        }
    }
}
