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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This defines the Renewing element inside the RequestSecurityToken message. 
    /// </summary>
    /// <remarks>
    /// The presence of Renewing element indicates the token issuer that the requested token
    /// can be renewed if allow attribute is true, and the token can be renewed after
    /// it expires if ok is true.
    /// </remarks>
    public class Renewing
    {
        /// <summary>
        /// Initializes a renewing object with specified allow and OK attributes.
        /// </summary>
        public Renewing(bool allowRenewal)
        : this (allowRenewal, false)
        {
        }

        /// <summary>
        /// Initializes a renewing object with specified allow and OK attributes.
        /// </summary>
        public Renewing( bool allowRenewal, bool okForRenewalAfterExpiration )
        {
            AllowRenewal = allowRenewal;
            OkForRenewalAfterExpiration = okForRenewalAfterExpiration;
        }

        /// <summary>
        /// Returns true if it is allowed to renew this token.
        /// </summary>
        /// <remarks>
        /// This optional boolean attribute is used to request a renewable token. Default value is true. 
        /// </remarks>
        /// <devdocs>
        /// Please refer to section 7 in the WS-Trust spec for more details.
        /// </devdocs>
        public bool AllowRenewal { get; }


        /// <summary>
        /// Returns true if the requested token can be renewed after it expires.
        /// </summary>
        /// <remarks>
        /// This optional boolean attriubte is used to indicate that a renewable token is acceptable if
        /// the requested duration exceeds the limit of the issuance service. That is, if true, then the 
        /// token can be renewed after their expiration. Default value is false for security reason. 
        /// </remarks>
        /// <devdocs>
        /// Please refer to section 7 in the WS-Trust spec for more details.
        /// </devdocs>
        public bool OkForRenewalAfterExpiration { get; }
    }
}
