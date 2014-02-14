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

    /// <summary>
    /// 
    /// </summary>
    internal static class IssuerKeyRetriever
    {
        public static SecurityTokenResolver CreateIssuerTokenResolver(string securityToken, TokenValidationParameters validationParameters)
        {
            List<SecurityToken> signingTokens = new List<SecurityToken>();
            // TODO: we need to stick with keys as they may be derived.
            List<SecurityKey> namedKeys = new List<SecurityKey>();
            foreach (SecurityKey securityKey in RetreiveIssuerSigningKeys(securityToken, validationParameters))
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
                        //signingTokens.Add(new X509SecurityToken())
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

            return SecurityTokenResolver.CreateDefaultSecurityTokenResolver(signingTokens.AsReadOnly(), true);
        }
        public static IEnumerable<SecurityKey> RetreiveIssuerSigningKeys(string securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters.RetreiveIssuerSigningKeys != null)
            {
                foreach (SecurityKey securityKey in validationParameters.RetreiveIssuerSigningKeys(securityToken))
                {
                    yield return securityKey;
                }
            }

            if (validationParameters != null)
            {
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
                    X509SecurityToken x509SecurityToken = validationParameters.IssuerSigningToken as X509SecurityToken;
                    if (x509SecurityToken != null)
                    {
                        yield return new X509SecurityKey(x509SecurityToken.Certificate);
                    }
                    else
                    {
                        foreach (SecurityKey securityKey in validationParameters.IssuerSigningToken.SecurityKeys)
                        {
                            yield return securityKey;
                        }
                    }
                }

                if (validationParameters.IssuerSigningTokens != null)
                {
                    foreach (SecurityToken token in validationParameters.IssuerSigningTokens)
                    {
                        X509SecurityToken x509SecurityToken = token as X509SecurityToken;
                        if (x509SecurityToken != null)
                        {
                            yield return new X509SecurityKey(x509SecurityToken.Certificate);
                        }
                        else
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
}
