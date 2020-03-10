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
    /// Provides string values for WsTrust fault codes.
    /// <para>Fault codes values for WsTrust Feb2005, 1.3 and 1.4 are the same.</para>
    /// </summary>
    public static class WsTrustFaultCodes
    {
        /// <summary>
        /// Gets the 'FailedAuthentication' fault code.
        /// </summary>
        public const string FailedAuthentication = "FailedAuthentication";

        /// <summary>
        /// Gets the 'FailedCheck' fault code.
        /// </summary>
        public const string FailedCheck = "FailedCheck";

        /// <summary>
        /// Gets the 'InvalidSecurity' fault code.
        /// </summary>
        public const string InvalidSecurity = "InvalidSecurity";

        /// <summary>
        /// Gets the 'InvalidSecurityToken' fault code.
        /// </summary>
        public const string InvalidSecurityToken = "InvalidSecurityToken";

        /// <summary>
        /// Gets the 'MessageExpired' fault code.
        /// </summary>
        public const string MessageExpired = "MessageExpired";

        /// <summary>
        /// Gets the 'SecurityTokenUnavailable' fault code.
        /// </summary>
        public const string SecurityTokenUnavailable = "SecurityTokenUnavailable";

        /// <summary>
        /// Gets the 'UnsupportedAlgorithm' fault code.
        /// </summary>
        public const string UnsupportedAlgorithm = "UnsupportedAlgorithm";

        /// <summary>
        /// Gets the 'UnsupportedSecurityToken' fault code.
        /// </summary>
        public const string UnsupportedSecurityToken = "UnsupportedSecurityToken";
    }
}
