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

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Constants for XML encryption attributes.
    /// <para>see: https://www.w3.org/TR/xmlenc-core1/ </para>
    /// </summary>
    internal static class XmlEncryptionAttributes
    {
        /// <summary>
        /// Gets the value for "Algorithm"
        /// </summary>
        public const string Algorithm = "Algorithm";

        /// <summary>
        /// Gets the value for "Encoding"
        /// </summary>
        public const string Encoding = "Encoding";

        /// <summary>
        /// Gets the value for "Id"
        /// </summary>
        public const string Id = "Id";

        /// <summary>
        /// Gets the value for "MimeType"
        /// </summary>
        public const string MimeType = "MimeType";

        /// <summary>
        /// Gets the value for "Recipient"
        /// </summary>
        public const string Recipient = "Recipient";

        /// <summary>
        /// Gets the value for "Type"
        /// </summary>
        public const string Type = "Type";

        /// <summary>
        /// Gets the value for "URI"
        /// </summary>
        public const string Uri = "URI";
    }
}
