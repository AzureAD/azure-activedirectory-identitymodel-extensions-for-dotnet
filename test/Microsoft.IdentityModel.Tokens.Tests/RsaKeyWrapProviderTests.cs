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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for KeyWrapProvider
    /// Constructors
    ///     - validate parameters (null, empty)
    ///     - algorithms supported
    ///     - properties are set correctly (Algorithm, Context, Key)
    /// WrapKey/UnwrapKey
    ///     - positive tests for keys Algorithms supported.
    ///     - parameter validation for WrapKey
    /// UnwrapKey
    ///     - parameter validataion for UnwrapKey
    /// UnwrapKeyMismatch
    ///     - negative tests for switching (keys, algorithms)
    /// WrapKeyVirtual
    ///     - tests virtual method was called
    /// UnwrapKeyVirtual
    ///     - tests virtual method was called
    /// </summary>
    public class RsaKeyWrapProviderTests
    {
        [Fact]
        public void UnwrapKey()
        {
            var provider = new DerivedRsaKeyWrapProvider(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaPKCS1, true);
            byte[] wrappedKey = provider.WrapKey(Guid.NewGuid().ToByteArray());
            provider.UnwrapKey(wrappedKey);
            Assert.True(provider.UnwrapKeyCalled);
        }

        [Fact]
        public void WrapKey()
        {
            var provider = new DerivedRsaKeyWrapProvider(KeyingMaterial.RsaSecurityKey1, SecurityAlgorithms.RsaPKCS1, false);
            byte[] wrappedKey = provider.WrapKey(Guid.NewGuid().ToByteArray());
            Assert.True(provider.WrapKeyCalled);
        }
    }
}
