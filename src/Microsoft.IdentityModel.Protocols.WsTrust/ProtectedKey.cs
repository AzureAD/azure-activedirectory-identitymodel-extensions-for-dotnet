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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This class are used in defining Entropy and RequestProofToken element inside the 
    /// RequestSecurityToken and RequestSecurityTokenResponse.
    /// </summary>
    public class ProtectedKey
    {        
        /// <summary>
        /// Use this constructor if we want to send the key material in clear text.
        /// </summary>
        /// <param name="secret">The key material that needs to be protected.</param>
        public ProtectedKey(byte[] secret)
        {
            Secret = secret;
        }

        /// <summary>
        /// 
        /// </summary>
        public ProtectedKey() { }
        /// <summary>
        /// Use this constructor if we want to send the key material encrypted.
        /// </summary>
        /// <param name="secret">The key material that needs to be protected.</param>
        /// <param name="wrappingCredentials">The encrypting credentials used to encrypt the key material.</param>
        public ProtectedKey(byte[] secret, EncryptingCredentials wrappingCredentials)
        {
            Secret = secret;
            WrappingCredentials = wrappingCredentials;
        }

        /// <summary>
        /// Gets the key material.
        /// </summary>
        public byte[] Secret { get; }

        /// <summary>
        /// Gets the encrypting credentials. Null means that the keys are not encrypted.
        /// </summary>
        public EncryptingCredentials WrappingCredentials { get; }
    }
}

