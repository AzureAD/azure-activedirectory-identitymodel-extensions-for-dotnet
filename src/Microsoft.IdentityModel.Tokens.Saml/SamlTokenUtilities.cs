using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// A class which contains useful methods for processing saml tokens.
    /// </summary>
    public class SamlTokenUtilities
    {
        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="tokenKeyInfo">The <see cref="KeyInfo"/> field of the token being validated</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        internal static SecurityKey ResolveTokenSigningKey(KeyInfo tokenKeyInfo, TokenValidationParameters validationParameters)
        {
            if (validationParameters.IssuerSigningKey != null && tokenKeyInfo.MatchesKey(validationParameters.IssuerSigningKey))
                return validationParameters.IssuerSigningKey;

            if (validationParameters.IssuerSigningKeys != null)
            {
                foreach (var key in validationParameters.IssuerSigningKeys)
                {
                    if (tokenKeyInfo.MatchesKey(key))
                        return key;
                }
            }

            return null;
        }

        /// <summary>
        /// Returns all <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="token">The <see cref="string"/> representation of the token that is being validated.</param>
        /// <param name="samlToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="tokenKeyInfo">The <see cref="KeyInfo"/> field of the token being validated</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> required for validation.</param>
        /// <param name="keyMatched">A <see cref="bool"/> to represent if a a issuer signing key matched with token kid or x5t</param>
        /// <returns>Returns all <see cref="SecurityKey"/> to use for signature validation.</returns>
        internal static IEnumerable<SecurityKey> GetKeysForTokenSignatureValidation(string token, SecurityToken samlToken, KeyInfo tokenKeyInfo, TokenValidationParameters validationParameters, out bool keyMatched)
        {
            keyMatched = false;

            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                return validationParameters.IssuerSigningKeyResolver(token, samlToken, tokenKeyInfo?.Id, validationParameters);
            }
            else
            {
                SecurityKey key = ResolveTokenSigningKey(tokenKeyInfo, validationParameters);

                if (key != null)
                {
                    keyMatched = true;
                    return new List<SecurityKey> { key };
                }
                else
                {
                    keyMatched = false;
                    if (validationParameters.TryAllIssuerSigningKeys)
                    {
                        return TokenUtilities.GetAllSigningKeys(validationParameters);
                    }
                }
            }
            return null;
        }
    }
}
