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
using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Compression provider abstract class.
    /// </summary>
    public abstract class CompressionProvider
    {
        private string _algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompressionProvider"/> class used for compression and decompression.
        /// </summary>
        /// <param name="algorithm">The compression algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        protected CompressionProvider(string algorithm)
        {
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the compression algorithm.
        /// </summary>
        public string Algorithm
        {
            get => _algorithm;
            private set => _algorithm = value ?? throw LogHelper.LogArgumentNullException("algorithm");
        }

        /// <summary>
        /// Called to determine if an algorithm is supported.
        /// </summary>
        /// <param name="algorithm">the algorithm that defines the compression method.</param>
        /// <returns>true if supported</returns>
        public abstract bool IsSupportedAlgorithm(string algorithm);

        /// <summary>
        /// Decompress.
        /// </summary>
        /// <param name="value">the value to decompress.</param>
        public abstract string Decompress(byte[] value);

        /// <summary>
        /// Compress.
        /// </summary>
        /// <param name="value">the value to decompress.</param>
        public abstract byte[] Compress(string value);
    }
}
