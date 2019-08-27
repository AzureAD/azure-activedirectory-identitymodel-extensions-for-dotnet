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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Classes for specifying WS-Trust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustVersion
    {
        public static WsTrustVersion TrustFeb2005 = new WsTrustFeb2005Version();

        public static WsTrustVersion Trust13 = new WsTrust13Version();

        public static WsTrustVersion Trust14 = new WsTrust14Version();
    }

    /// <summary>
    /// Class for specifying WS-Trust Feb2005.
    /// </summary>
    internal class WsTrustFeb2005Version : WsTrustVersion {}

    /// <summary>
    /// Class for specifying WS-Trust 1.3.
    /// </summary>
    internal class WsTrust13Version : WsTrustVersion {}

    /// <summary>
    /// Class for specifying WS-Trust 1.4.
    /// </summary>
    internal class WsTrust14Version : WsTrustVersion {}
}
