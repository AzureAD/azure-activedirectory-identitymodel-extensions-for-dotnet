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

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants for WS-Security attributes.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public static class WsSecurityAttributes
    {
        /// <summary>
        /// Gets the value for "EncodingType"
        /// </summary>
        public const string EncodingType = "EncodingType";

        /// <summary>
        /// Gets the value for "Id"
        /// </summary>
        public const string Id = "Id";

        // WsSecurity 1.1 {2004}
        /// <summary>
        /// Gets the value for "TokenType"
        /// </summary>
        public const string TokenType = "TokenType";

        /// <summary>
        /// Gets the value for "Type"
        /// </summary>
        public const string Type = "Type";

        /// <summary>
        /// Gets the value for "URI"
        /// </summary>
        public const string URI = "URI";

        /// <summary>
        /// Gets the value for "Usage"
        /// </summary>
        public const string Usage = "Usage";

        /// <summary>
        /// Gets the value for "ValueType"
        /// </summary>
        public const string ValueType = "ValueType";
    }
}
