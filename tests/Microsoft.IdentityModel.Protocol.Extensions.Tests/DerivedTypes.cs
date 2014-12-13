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

// This file contains derived types that are usefull across multiple handlers / protocols.

namespace Microsoft.IdentityModel.Test
{
    using System;
    using System.IdentityModel.Tokens;
    
    /// <summary>
    /// Used to return a specific token and key.
    /// Helpful when forcing a failure, or testing extensibility
    /// </summary>
    public class SetReturnSecurityTokenResolver : SecurityTokenResolver
    {
        public SetReturnSecurityTokenResolver(SecurityToken token, SecurityKey key)
        {
            SecurityKey = key;
            SecurityToken = token;
        }

        public SecurityKey SecurityKey { get; set; }
        public SecurityToken SecurityToken { get; set; }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = SecurityKey;
            return true;
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            token = SecurityToken;
            return true;
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            token = SecurityToken;
            return true;
        }
    }

    /// <summary>
    /// Can return a specific issuer name.
    /// </summary>
    public class SetNameIssuerNameRegistry : IssuerNameRegistry
    {
        private string _issuer;
        public SetNameIssuerNameRegistry(string issuer)
        {
            _issuer = issuer;
        }

        public override string GetIssuerName(SecurityToken securityToken, string requestedIssuerName)
        {
            return _issuer;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            return _issuer;
        }
    }

    public class AlwaysSucceedCertificateValidator : X509CertificateValidator
    {
        public override void Validate(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            return;
        }

        public static AlwaysSucceedCertificateValidator New { get { return new AlwaysSucceedCertificateValidator(); } }
    }

    public class AlwaysThrowCertificateValidator : X509CertificateValidator
    {
        private Exception _exception = new SecurityTokenValidationException("Certificate not valid");

        public Exception Exception
        {
            get { return _exception; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("Exception");
                }

                _exception = value;
            }
        }

        public override void Validate(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            throw Exception;
        }
    }
}