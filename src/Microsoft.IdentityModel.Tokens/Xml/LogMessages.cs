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

namespace Microsoft.IdentityModel.Tokens.Xml
{
    /// <summary>
    /// Log messages and codes for XmlProcessing
    /// Range: IDX21010 - IDX21200
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        internal const string IDX21023 = "IDX21023: Unsupported NodeType: {0}.";
        internal const string IDX21204 = "IDX21204: Canonicalization algorithm is not supported: '{0}'. Supported methods are: '{1}', '{2}'.";
        internal const string IDX21210 = "IDX21210: The TransformFactory does not support the transform: '{0}'.";
        internal const string IDX21211 = "IDX21211: The TransfromFactory does not support the canonicalizing transform: '{0}'.";
        internal const string IDX21102 = "IDX21102: The reader must be pointing to a StartElement. NodeType is: '{0}'.";
        internal const string IDX21207 = "IDX21207: SignatureMethod is not supported: '{0}'. CryptoProviderFactory: '{1}'.";
        internal const string IDX21208 = "IDX21208: InnerReader is null. It is necessary to set InnerReader before making calls to DelegatingXmlDictionaryReader.";
        internal const string IDX21209 = "IDX21209: InnerWriter is null. It is necessary to set InnerWriter before making calls to DelegatingXmlDictionaryWriter.";
#pragma warning restore 1591
    }
}
