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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants for WS-Trust attributes.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public static class WsTrustAttributes
    {
        /// <summary>
        /// Gets the value for "Allow"
        /// </summary>
        public const string Allow = "Allow";

        /// <summary>
        /// Gets the value for "Context"
        /// </summary>
        public const string Context = "Context";

        /// <summary>
        /// Gets the value for "Dialect"
        /// </summary>
        public const string Dialect = "Dialect";

        /// <summary>
        /// Gets the value for "EncodingType"
        /// </summary>
        public const string EncodingType = "EncodingType";

        /// <summary>
        /// Gets the value for "KeyExchangeToken"
        /// </summary>
        public const string KeyExchangeToken = "KeyExchangeToken";

        /// <summary>
        /// Gets the value for "OK"
        /// </summary>
        public const string OK = "OK";

        /// <summary>
        /// Gets the value for "RequestKET"
        /// </summary>
        public const string RequestKET = "RequestKET";

        /// <summary>
        /// Gets the value for "Sig"
        /// </summary>
        public const string Sig = "Sig";

        /// <summary>
        /// Gets the value for "Type"
        /// </summary>
        public const string Type = "Type";

        /// <summary>
        /// Gets the value for "ValueType"
        /// </summary>
        public const string ValueType = "ValueType";
    }
}
