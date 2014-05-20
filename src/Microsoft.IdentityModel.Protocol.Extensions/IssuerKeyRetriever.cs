//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Extensions
{
    // TODO - for SAML 1 and 2 tokens, we don't want to create a collection, so when finished this 
    // new class will resolve the token without creating a collection of securityTokens which results in creating new keys
    // from certs, keys may be linked to hardware and should not be recreated.
    internal class IssuerTokenResolver : SecurityTokenResolver
    {
        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = null;
            if (keyIdentifierClause.CanCreateKey)
            {
                key = keyIdentifierClause.CreateKey();
                return true;
            }

            return false;
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            throw new System.NotImplementedException();
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            token = null;
            return false;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    internal static class IssuerKeyRetriever
    {

        // 
        // TODO - this method is not complete
        // It needs to be dynamic, ie: do not create a list of tokens from TokenValidationParameters.IssuerSigningtokens, IssuerSigningKeys, IssuerSigningKeyRetriever for keys.
        // the class above is being developed to handle matching SecurityKeys and handling dynamic key matching.
        // 
        // Consider it a stop-gap solution that handles the 60% case and allows early adopters to experiment and with samples.

        /// <summary>
        /// Used to create signing tokens when reading SamlTokens (1&2) as reading requires a token to validate signature.
        /// </summary>
        /// <param name="securityToken"></param>
        /// <param name="validationParameters"></param>
        /// <returns></returns>
        public static SecurityTokenResolver CreateIssuerTokenResolver(string securityToken, TokenValidationParameters validationParameters)
        {

            // X509SecurityKey (s)
            List<SecurityToken> signingTokens = new List<SecurityToken>();
            if (validationParameters.IssuerSigningToken != null)
            {
                signingTokens.Add(validationParameters.IssuerSigningToken);
            }

            if (validationParameters.IssuerSigningTokens != null)
            {
                signingTokens.AddRange(validationParameters.IssuerSigningTokens);
            }

            List<SecurityKey> namedKeys = new List<SecurityKey>();
            foreach (SecurityKey securityKey in RetrieveIssuerSigningKeys(securityToken, validationParameters))
            {
                X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
                if (x509SecurityKey != null)
                {
                    signingTokens.Add(new X509SecurityToken(x509SecurityKey.Certificate));
                }
                else
                {
                    X509AsymmetricSecurityKey x509AsymmetricSecurityKey = securityKey as X509AsymmetricSecurityKey;
                    if (x509AsymmetricSecurityKey != null)
                    {
                        // TODO finish up IssuerTokenResolver so it can be returned instead of creating a 'copied' list of tokens.
                        // signingTokens.Add(new X509SecurityToken())
                    }
                    else
                    {
                        namedKeys.Add(securityKey);
                    }
                }
            }

            if (namedKeys.Count > 0)
            {
                signingTokens.Add(new NamedKeySecurityToken("unknown", namedKeys));
            }

            // TODO - finish up IssuerTokenResolver so it can be returned instead of creating a 'copied' list of tokens.
            // return new IssuerTokenResolver();

            return SecurityTokenResolver.CreateDefaultSecurityTokenResolver(signingTokens.AsReadOnly(), true);
        }

        public static IEnumerable<SecurityKey> RetrieveIssuerSigningKeys(string securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters != null)
            {
                if (validationParameters.IssuerSigningKeyRetriever != null)
                {
                    foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeyRetriever(securityToken))
                    {
                        yield return securityKey;
                    }
                }

                if (validationParameters.IssuerSigningKey != null)
                {
                    yield return validationParameters.IssuerSigningKey;
                }

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeys)
                    {
                        yield return securityKey;
                    }
                }

                if (validationParameters.IssuerSigningToken != null && validationParameters.IssuerSigningToken.SecurityKeys != null)
                {
                    foreach (SecurityKey securityKey in validationParameters.IssuerSigningToken.SecurityKeys)
                    {
                        yield return securityKey;
                    }
                }

                if (validationParameters.IssuerSigningTokens != null)
                {
                    foreach (SecurityToken token in validationParameters.IssuerSigningTokens)
                    {
                        if (token.SecurityKeys != null)
                        {
                            foreach (SecurityKey securityKey in token.SecurityKeys)
                            {
                                yield return securityKey;
                            }
                        }
                    }
                }
            }
        }
    }
}
