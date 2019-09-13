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

using Microsoft.IdentityModel.Tokens;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    public interface IPopTokenValidator
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="popToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="popTokenValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<PopTokenValidationResult> ValidatePopTokenAsync(string popToken, HttpRequestData httpRequestData, TokenValidationParameters tokenValidationParameters, PopTokenValidationPolicy popTokenValidationPolicy, CancellationToken cancellationToken);
    }
}