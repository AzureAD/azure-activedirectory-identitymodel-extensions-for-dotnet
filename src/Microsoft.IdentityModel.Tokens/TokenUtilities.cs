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

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// A class which contains useful methods for processing tokens.
    /// </summary>
    public class TokenUtilities
    {
        /// <summary>
        /// Returns all <see cref="SecurityKey"/> provided in validationParameters.
        /// </summary>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>Returns all <see cref="SecurityKey"/> provided in validationParameters.</returns>
        internal static IEnumerable<SecurityKey> GetAllSigningKeys(TokenValidationParameters validationParameters)
        {
            LogHelper.LogInformation(TokenLogMessages.IDX10243);
            if (validationParameters.IssuerSigningKey != null)
                yield return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
                foreach (SecurityKey key in validationParameters.IssuerSigningKeys)
                    yield return key;
        }

        /// <summary>
        /// Merges claims, If an item with same type exists in both the lists, the one in claims is picked.
        /// </summary>
        /// <param name="claims">Collection of claims.</param>
        /// <param name="subjectClaims">Collection of claims.</param>
        /// <param name="replace">Tells to either replace repeating items in subjectClaims or keep them.</param>
        /// <returns></returns>
        internal static IEnumerable<Claim> MergeClaims(IEnumerable<Claim> claims, IEnumerable<Claim> subjectClaims, bool replace)
        {
            if (claims == null)
                return subjectClaims;

            if (subjectClaims == null)
                return claims;

            List<Claim> result = claims.ToList();
            if (replace)
            {
                foreach (Claim claim in subjectClaims)
                {
                    if (claims.Where(i => i.Type == claim.Type).FirstOrDefault() == null)
                    {
                        result.Add(claim);
                    }
                }
                return result;
            }
            else
                return result.Concat(subjectClaims);
        }

        /// <summary>
        /// Gets ValueType of the claim from it's Value.
        /// </summary>
        /// <param name="value">Represents value of a claim.</param>
        /// <returns>String representing claim's ValueType.</returns>
        internal static string GetClaimValueTypeFromValue(object value)
        {
            if (value.GetType().Name == typeof(String).Name)
            {
                return ClaimValueTypes.String;
            }
            if (value.GetType().Name == typeof(Boolean).Name)
            {
                return ClaimValueTypes.Boolean;
            }
            if (value.GetType().Name == typeof(Int32).Name)
            {
                return ClaimValueTypes.Integer32;
            }
            if (value.GetType().Name == typeof(Int64).Name)
            {
                return ClaimValueTypes.Integer64;
            }
            if (value.GetType().Name == typeof(Double).Name)
            {
                return ClaimValueTypes.Double;
            }
            if (value.GetType().Name == typeof(DateTime).Name)
            {
                return ClaimValueTypes.DateTime;
            }
            if (value.GetType().Name == typeof(List<>).Name)
            {
                foreach (var item in (IList)value)
                {
                    return GetClaimValueTypeFromValue(item);
                }
            }
            return null;
        }
    }
}
