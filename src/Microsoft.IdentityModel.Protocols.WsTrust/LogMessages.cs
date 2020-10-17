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

// Microsoft.IdentityModel.Protocols.WsTrust
// Range: 15000 - 15999

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Log messages for WsTrust IDX15000 to IDX15999
    /// </summary>
    internal static class LogMessages
    {
        // ========================================================================================================================
        // copied from M.IM.XML

        internal const string IDX15000 = "IDX15000: Unknown WS-Trust namespace. Expecting Element: '{0}' to be in one of three namespaces: '{1}', '{2}', '{3}'. Found namespace '{4}'.";
        internal const string IDX15001 = "IDX15001: Unknown WS-Addressing namespace. Expecting Element: '{0}' to be in one of two namespaces: '{1}', '{2}'. Found namespace '{3}'.";

        // XML reading
        internal const string IDX15011 = "IDX15011: Unable to read XML. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.";
        internal const string IDX15013 = "IDX15013: Unable to read XML. While reading element '{0}', Required attribute was not found : '{1}'.";
        internal const string IDX15016 = "IDX15016: Exception thrown while reading '{0}'. See inner exception for more details.";
        internal const string IDX15017 = "IDX15017: Exception thrown while reading '{0}'. Caught exception: '{1}'.";
        internal const string IDX15022 = "IDX15022: Unable to read XML. Expecting XmlReader to be at a StartElement, NodeType is: '{0}'.";
        internal const string IDX15024 = "IDX15024: Unable to read XML. Expecting XmlReader to be at element: '{0}', found: '{1}'.";
        internal const string IDX15407 = "IDX15407: Exception caught while writing: '{0}'. Caught exception: '{1}'.";

        // copied from M.IM.XML
        // ========================================================================================================================

        // IDX15100 - specific WsTrustReadRequest errors
        internal const string IDX15101 = "IDX15101: Unable to read OnBehalfOf Element. Unable to read token: '{0}'.";

        // IDX15500 - class creation errors and warnings
        internal const string IDX15500 = "IDX15500: Lifetime constructed with expires <= created.";

        // KeyGeneration errors
        public const string IDX15850 = "IDX15850: '{0}' cannot be less than zero. Was: '{1}'.";
        public const string IDX15851 = "IDX15851: '{0}' must be a multiple of 8. Was: '{1}'.";
        public const string IDX15852 = "IDX15852: Key size requested: '{0}', must be larger than '{1}' and smaller than '{2}'.";
        public const string IDX15853 = "IDX15853: Invalid issuerEntropy size. issuerEntropy.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.";
        public const string IDX15854 = "IDX15854: Invalid requestorEntropy size. requestorEntropy.Length: '{0}', must be larger than '{1}' and smaller than '{2}'.";
    }
}
