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
    /// Provides string values for WsTrust attributes.
    /// <para>Attribute values for WsTrust Feb2005, 1.3 and 1.4 are the same.</para>
    /// </summary>
    public static class WsTrustAttributes
    {
        /// <summary>
        /// Gets the 'Allow' attribute.
        /// </summary>
        public const string Allow = "Allow";

        /// <summary>
        /// Gets the 'Context' attribute.
        /// </summary>
        public const string Context = "Context";

        /// <summary>
        /// Gets the 'Dialect' attribute.
        /// </summary>
        public const string Dialect = "Dialect";

        /// <summary>
        /// Gets the 'EncodingType' attribute.
        /// </summary>
        public const string EncodingType = "EncodingType";

        /// <summary>
        /// Gets the 'KeyExchangeToken' attribute.
        /// </summary>
        public const string KeyExchangeToken = "KeyExchangeToken";

        /// <summary>
        /// Gets the 'OK' attribute.
        /// </summary>
        public const string OK = "OK";

        /// <summary>
        /// Gets the 'RequestKET' attribute.
        /// </summary>
        public const string RequestKET = "RequestKET";

        /// <summary>
        /// Gets the 'Sig' attribute.
        /// </summary>
        public const string Sig = "Sig";

        /// <summary>
        /// Gets the 'Type' attribute.
        /// </summary>
        public const string Type = "Type";

        /// <summary>
        /// Gets the 'ValueType' attribute.
        /// </summary>
        public const string ValueType = "ValueType";
    }
}
