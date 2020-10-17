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

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Constants: XML Encryption namespace and prefix.
    /// <para>see: https://www.w3.org/TR/xmlenc-core1/ </para>
    /// </summary>
    internal abstract class XmlEncryptionConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static readonly IList<string> KnownNamespaces = new List<string> { "http://www.w3.org/2001/04/xmlenc#" };

        /// <summary>
        /// Gets constants for XML Encryption 1.1
        /// </summary>
        public static XmlEncryption11Constants XmlEnc11 { get; } = new XmlEncryption11Constants();
    }

    /// <summary>
    /// Constants: XML Encryption 1.1 namespace and prefix.
    /// </summary>
    internal class XmlEncryption11Constants : XmlEncryptionConstants
    {
        /// <summary>
        /// Instantiates XML Encryption 1.1
        /// </summary>
        public XmlEncryption11Constants()
        {
            Namespace = "http://www.w3.org/2001/04/xmlenc#";
            Prefix = "xenc";
        }
    }
}
