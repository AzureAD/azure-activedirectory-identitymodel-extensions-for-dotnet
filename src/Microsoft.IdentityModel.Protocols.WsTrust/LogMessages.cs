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
        internal const string IDX15000 = "IDX15000: Unknown Ws-Trust namespace. Expecting Element: '{0}' to be in one of three namespaces: '{1}', '{2}', '{3}'. Found namespace '{4}'.";
        internal const string IDX15001 = "IDX15001: Unknown Ws-Addressing namespace. Expecting Element: '{0}' to be in one of two namespaces: '{1}', '{2}'. Found namespace '{3}'.";

        // IDX15100 - specific WsTrustReadRequest errors
        // internal const string IDX15100 = "IDX15100: WsTrustRequest must start with a '{0}' element.";
        internal const string IDX15101 = "IDX15101: Unable to read OnBehalfOf Element. Unable to read token: '{0}'.";

        // IDX15500 - class creation errors and warnings
        internal const string IDX15500 = "IDX15500: Lifetime constructed with expires <= created.";
    }
}
