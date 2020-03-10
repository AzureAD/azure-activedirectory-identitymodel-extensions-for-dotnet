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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a BinarySecret element.
    /// A binary secret represents key material that will be serialized with a request.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class BinarySecret
    {
        private byte[] _data;
        private string _encodingType;

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// This constructor is useful when deserializing from xml.
        /// </summary>
        public BinarySecret()
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// </summary>
        /// <param name="data">the bytes of the key material.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data"/> is null.</exception>
        public BinarySecret(byte[] data)
        {
            Data = data;
        }

        /// <summary>
        /// Creates an instance of <see cref="BinarySecret"/>.
        /// </summary>
        /// <param name="data">the bytes of the key material.</param>
        /// <param name="encodingType">the encoding type to use when writing data.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encodingType"/> is null or an empty string.</exception>
        public BinarySecret(byte[] data, string encodingType)
        {
            Data = data;
            EncodingType = encodingType;
        }

        /// <summary>
        /// Gets or sets the binary data.
        /// </summary>
        /// <exception cref="ArgumentNullException">if Data is null.</exception>
        public byte[] Data
        {
            get => _data;
            set => _data = value ?? throw LogHelper.LogArgumentNullException(nameof(Data));
        }

        /// <summary>
        /// Gets or sets the encoding type.
        /// </summary>
        public string EncodingType
        {
            get => _encodingType;
            set => _encodingType = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(EncodingType)) : value;
        }

        /// <summary>
        /// A collection of additional attributes.
        /// </summary>
        public ICollection<string> AdditionalAttributes { get; } = new Collection<string>();
    }
}
