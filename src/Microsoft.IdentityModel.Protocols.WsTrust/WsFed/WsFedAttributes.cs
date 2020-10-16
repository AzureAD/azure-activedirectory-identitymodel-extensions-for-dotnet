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

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Constants for WS-Federation attributes.
    /// see: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
    /// </summary>
    public static class WsFedAttributes
    {
        /// <summary>
        /// Gets the value for "Dialect"
        /// </summary>
        public const string Dialect = "Dialect";

        /// <summary>
        /// Gets the value for "Name"
        /// </summary>
        public const string Name = "Name";

        /// <summary>
        /// Gets the value for "Optional"
        /// </summary>
        public const string Optional = "Optional";

        /// <summary>
        /// Gets the value for "Scope"
        /// </summary>
        public const string Scope = "Scope";

        /// <summary>
        /// Gets the value for "Uri"
        /// </summary>
        public const string Uri = "Uri";
    }
}
