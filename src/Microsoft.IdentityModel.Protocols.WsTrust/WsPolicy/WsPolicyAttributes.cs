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

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Constants: WS-Policy attribute names.
    /// <para>see: http://specs.xmlsoap.org/ws/2004/09/policy/ws-policy.pdf </para>
    /// </summary>
    public static class WsPolicyAttributes
    {
        /// <summary>
        /// Gets the value for "Digest"
        /// </summary>
        public const string Digest = "Digest";

        /// <summary>
        /// Gets the value for "DigestAlgorithm"
        /// </summary>
        public const string DigestAlgorithm = "DigestAlgorithm";

        /// <summary>
        /// Gets the value for "Optional"
        /// </summary>
        public const string Optional = "Optional";

        /// <summary>
        /// Gets the value for "PolicyURIs"
        /// </summary>
        public const string PolicyURIs = "PolicyURIs";

        /// <summary>
        /// Gets the value for "TargetNamespace"
        /// </summary>
        public const string TargetNamespace = "TargetNamespace";

        /// <summary>
        /// Gets the value for "URI"
        /// </summary>
        public const string URI = "URI";
    }
}
