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

// Microsoft.IdentityModel.Tokens.Xml
// Range: 14000 - 14999

namespace Microsoft.IdentityModel.Tokens.Xml
{
    /// <summary>
    /// Log messages and codes for XmlProcessing
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        internal const string IDX14023 = "IDX14023: Unsupported NodeType: {0}.";
        internal const string IDX14210 = "IDX14210: The TransformFactory does not support the transform: '{0}'.";
        internal const string IDX14211 = "IDX14211: The TransfromFactory does not support the canonicalizing transform: '{0}'.";
        internal const string IDX14102 = "IDX14102: The reader must be pointing to a StartElement. NodeType is: '{0}'.";
        internal const string IDX14208 = "IDX14208: InnerReader is null. It is necessary to set InnerReader before making calls to DelegatingXmlDictionaryReader.";
        internal const string IDX14209 = "IDX14209: InnerWriter is null. It is necessary to set InnerWriter before making calls to DelegatingXmlDictionaryWriter.";
#pragma warning restore 1591
    }
}
