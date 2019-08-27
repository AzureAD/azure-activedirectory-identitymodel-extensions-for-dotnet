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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the BinaryExchange element.  
    /// </summary>
    public class BinaryExchange
    {
        /// <summary>
        /// Creates an instance of <see cref="BinaryExchange"/>
        /// </summary>
        /// <param name="binaryData">Binary data exchanged.</param>
        /// <param name="valueType">Uri representing the value type of the binary data.</param>
        /// <exception cref="ArgumentNullException">Input parameter 'binaryData' or 'valueType' is null.</exception>
        public BinaryExchange( byte[] binaryData, Uri valueType )
            : this( binaryData, valueType, new Uri( WsSecurityEncodingTypes.WsSecurity10.Base64 ) )
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="BinaryExchange"/>
        /// </summary>
        /// <param name="binaryData">Binary data exchanged.</param>
        /// <param name="valueType">Uri representing the value type of the binary data.</param>
        /// <param name="encodingType">Encoding type to be used for encoding teh </param>
        /// <exception cref="ArgumentNullException">Input parameter 'binaryData', 'valueType' or 'encodingType' is null.</exception>
        public BinaryExchange( byte[] binaryData, Uri valueType, Uri encodingType )
        {
            // [TODO - brentsch] should we allow strings instead of Uri 
            BinaryData = binaryData ?? throw LogHelper.LogArgumentNullException(nameof(binaryData));
            ValueType = valueType ?? throw LogHelper.LogArgumentNullException(nameof(ValueType)); ;
            EncodingType = encodingType ?? throw LogHelper.LogArgumentNullException(nameof(EncodingType)); ;
        }

        /// <summary>
        /// Gets the Binary Data.
        /// </summary>
        public byte[] BinaryData { get; }

        /// <summary>
        /// Gets the ValueType Uri.
        /// </summary>
        public Uri ValueType { get; }

        /// <summary>
        /// Gets the EncodingType Uri.
        /// </summary>
        public Uri EncodingType { get; }
    }
}
