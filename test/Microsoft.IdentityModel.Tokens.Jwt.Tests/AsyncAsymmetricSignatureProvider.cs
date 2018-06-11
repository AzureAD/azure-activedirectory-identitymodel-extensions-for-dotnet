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

using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens.Jwt.Tests
{
    public class AsyncAsymmetricSignatureProvider: AsymmetricSignatureProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsyncAsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.<see cref="SecurityKey"/></param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        public AsyncAsymmetricSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
            : base(key, algorithm, willCreateSignatures)
        {
        }

        public override async Task<byte[]> SignAsync(byte[] input)
        {
            await Task.Delay(2000);
            return base.Sign(input);
        }

        public override async Task<bool> VerifyAsync(byte[] input, byte[] signature)
        {
            await Task.Delay(2000);
            return base.Verify(input, signature);
        }
    }
}
