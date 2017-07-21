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

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Resolves securitykeys, used when working with Saml1 and Saml2 tokens as the EnvelopingSignatureReader needs this 
    /// to find keys.
    /// </summary>
    internal class SecurityKeyResolver : SecurityTokenResolver
    {
        private delegate bool CertMatcher(X509Certificate2 cert);

        private static FieldInfo _certFieldInfo;
        private static Type _x509AsymmKeyType;

        private string _securityToken;
        private TokenValidationParameters _validationParameters;

        static SecurityKeyResolver()
        {
            _x509AsymmKeyType = typeof(X509AsymmetricSecurityKey);
            _certFieldInfo = _x509AsymmKeyType.GetField("certificate", BindingFlags.NonPublic | BindingFlags.Instance);
        }
        /// <summary>
        /// Creates a new instance of <see cref="SecurityKeyResolver"/>
        /// </summary>
        /// <param name="securityToken">related security token.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        public SecurityKeyResolver(string securityToken, TokenValidationParameters validationParameters)
        {
            _securityToken = securityToken;

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            _validationParameters = validationParameters;

            this.IsKeyMatched = false;
        }

        public bool IsKeyMatched { get; set; }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> that matches the <see cref="SecurityKeyIdentifierClause"/>
        /// </summary>
        /// <param name="keyIdentifierClause">clause to match.</param>
        /// <param name="key">key to assign.</param>
        /// <returns>true if matched.</returns>
        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            SecurityToken token = null;
            return ResolvesToSigningToken(keyIdentifierClause, out key, out token);
        }

        /// <summary>
        /// Sets a <see cref="SecurityKey"/> that matches the <see cref="SecurityKeyIdentifierClause"/>
        /// </summary>
        /// <param name="keyIdentifierClause">clause to match.</param>
        /// <param name="token">token to assign.</param>
        /// <returns>throws <see cref="NotImplementedException"/>.</returns>
        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// Sets a <see cref="SecurityToken"/> that matches the <see cref="SecurityKeyIdentifier"/>
        /// </summary>
        /// <param name="keyIdentifier">keyidentifier to match.</param>
        /// <param name="token">token to set.</param>
        /// <returns>true if matched.</returns>
        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            token = null;
            foreach (var keyIdentifierClause in keyIdentifier)
            {
                SecurityKey key = null;
                if (ResolvesToSigningToken(keyIdentifierClause, out key, out token))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool Matches(SecurityKeyIdentifierClause keyIdentifierClause, SecurityKey key, CertMatcher certMatcher, out SecurityToken token)
        {
            token = null;
            if (certMatcher != null)
            {
                X509SecurityKey x509Key = key as X509SecurityKey;
                if (x509Key != null)
                {
                    if (certMatcher(x509Key.Certificate))
                    {
                        token = new X509SecurityToken(x509Key.Certificate);
                        return true;
                    }
                }
                else
                {
                    X509AsymmetricSecurityKey x509AsymmKey = key as X509AsymmetricSecurityKey;
                    if (x509AsymmKey != null)
                    {
                        X509Certificate2 cert = _certFieldInfo.GetValue(x509AsymmKey) as X509Certificate2;
                        if (cert != null && certMatcher(cert))
                        {
                            token = new X509SecurityToken(cert);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private bool ResolvesToSigningToken(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key, out SecurityToken token)
        {
            token = null;
            key = null;
            CertMatcher certMatcher = null;

            // for SAML tokens the highest probability are certs, with RawData first
            X509RawDataKeyIdentifierClause rawCertKeyIdentifierClause = keyIdentifierClause as X509RawDataKeyIdentifierClause;
            if (rawCertKeyIdentifierClause != null)
            {
                certMatcher = rawCertKeyIdentifierClause.Matches;
            }
            else
            {
                X509SubjectKeyIdentifierClause subjectKeyIdentifierClause = keyIdentifierClause as X509SubjectKeyIdentifierClause;
                if (subjectKeyIdentifierClause != null)
                {
                    certMatcher = subjectKeyIdentifierClause.Matches;
                }
                else
                {
                    X509ThumbprintKeyIdentifierClause thumbprintKeyIdentifierClause = keyIdentifierClause as X509ThumbprintKeyIdentifierClause;
                    if (thumbprintKeyIdentifierClause != null)
                    {
                        certMatcher = thumbprintKeyIdentifierClause.Matches;
                    }
                    else
                    {
                        X509IssuerSerialKeyIdentifierClause issuerKeyIdentifierClause = keyIdentifierClause as X509IssuerSerialKeyIdentifierClause;
                        if (issuerKeyIdentifierClause != null)
                        {
                            certMatcher = issuerKeyIdentifierClause.Matches;
                        }
                    }
                }
            }

            if (_validationParameters.IssuerSigningKeyResolver != null)
            {
                key = _validationParameters.IssuerSigningKeyResolver(token: _securityToken, securityToken: null, keyIdentifier: new SecurityKeyIdentifier(keyIdentifierClause), validationParameters: _validationParameters);
                if (key != null)
                {
                    this.IsKeyMatched = true;
                }
            }

            if (_validationParameters.IssuerSigningKey != null)
            {
                if (Matches(keyIdentifierClause, _validationParameters.IssuerSigningKey, certMatcher, out token))
                {
                    key = _validationParameters.IssuerSigningKey;
                    this.IsKeyMatched = true;
                }
            }

            if (_validationParameters.IssuerSigningKeys != null)
            {
                foreach (SecurityKey securityKey in _validationParameters.IssuerSigningKeys)
                if (Matches(keyIdentifierClause, securityKey, certMatcher, out token))
                {
                    key = securityKey;
                    this.IsKeyMatched = true;
                    break;
                }
            }

            if (_validationParameters.IssuerSigningToken != null)
            {
                if (_validationParameters.IssuerSigningToken.MatchesKeyIdentifierClause(keyIdentifierClause))
                {
                    token = _validationParameters.IssuerSigningToken;
                    key = token.SecurityKeys[0];
                    this.IsKeyMatched = true;
                }
            }

            if (_validationParameters.IssuerSigningTokens != null)
            {
                foreach (SecurityToken issuerToken in _validationParameters.IssuerSigningTokens)
                {
                    if (_validationParameters.IssuerSigningToken.MatchesKeyIdentifierClause(keyIdentifierClause))
                    {
                        token = issuerToken;
                        key = token.SecurityKeys[0];
                        this.IsKeyMatched = true;
                        break;
                    }
                }
            }

            return this.IsKeyMatched;
        }
    }
}
