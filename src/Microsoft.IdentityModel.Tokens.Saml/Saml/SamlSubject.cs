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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlSubject
    {
        // Saml SubjectConfirmation parts.
        Collection<string> _confirmationMethods = new Collection<string>();
        string _confirmationData;
        SecurityKeyIdentifier _securityKeyIdentifier;
        SecurityKey _crypto;

        // Saml NameIdentifier element parts.
        string _name;
        string _nameFormat;
        string _nameQualifier;

        // TODO remove this internal
        internal SamlSubject()
        {
        }

        public SamlSubject(string nameFormat, string nameQualifier, string name)
            : this(nameFormat, nameQualifier, name, null, null, null)
        {
        }

        public SamlSubject(
            string nameFormat,
            string nameQualifier,
            string name,
            IEnumerable<string> confirmations,
            string confirmationData,
            SecurityKeyIdentifier securityKeyIdentifier)
        {
            if (confirmations != null)
            {
                foreach (string method in confirmations)
                {
                    if (string.IsNullOrEmpty(method))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                    _confirmationMethods.Add(method);
                }
            }

            if ((_confirmationMethods.Count == 0) && (string.IsNullOrEmpty(name)))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresNameIdentifierOrConfirmationMethod"));

            if ((_confirmationMethods.Count == 0) && ((confirmationData != null) || (securityKeyIdentifier != null)))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresConfirmationMethodWhenConfirmationDataOrKeyInfoIsSpecified"));

            _name = name;
            _nameFormat = nameFormat;
            _nameQualifier = nameQualifier;
            _confirmationData = confirmationData;
            _securityKeyIdentifier = securityKeyIdentifier;
        }

        public string Name
        {
            get { return _name; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _name = value;
            }
        }

        // TODO - can this be null
        public string NameFormat
        {
            get; set;
        }

        // TODO - can this be null
        public string NameQualifier
        {
            get; set;
        }

        public static string NameClaimType
        {
            get
            {
                return ClaimTypes.NameIdentifier;
            }
        }

        public ICollection<string> ConfirmationMethods
        {
            get { return _confirmationMethods; }
        }

        public string ConfirmationData
        {
            get
            {
                return _confirmationData;
            }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _confirmationData = value;
            }
        }

        public SecurityKeyIdentifier KeyIdentifier
        {
            get { return _securityKeyIdentifier; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _securityKeyIdentifier = value;
            }
        }

        // TODO - surface here or from assertion / token
        public SecurityKey Key
        {
            get { return _crypto; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _crypto = value;
            }
        }

        void CheckObjectValidity()
        {
            if ((_confirmationMethods.Count == 0) && (string.IsNullOrEmpty(_name)))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresNameIdentifierOrConfirmationMethod"));

            if ((_confirmationMethods.Count == 0) && ((_confirmationData != null) || (_securityKeyIdentifier != null)))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresConfirmationMethodWhenConfirmationDataOrKeyInfoIsSpecified"));
        }

        // TODO - get out claims
        //public virtual ReadOnlyCollection<Claim> ExtractClaims()
        //{
        //    if (this.claims == null)
        //    {
        //        this.claims = new List<Claim>();
        //        if (!string.IsNullOrEmpty(this.name))
        //        {
        //            this.claims.Add(new Claim(ClaimTypes.NameIdentifier, new SamlNameIdentifierClaimResource(this.name, this.nameQualifier, this.nameFormat), Rights.Identity));
        //            this.claims.Add(new Claim(ClaimTypes.NameIdentifier, new SamlNameIdentifierClaimResource(this.name, this.nameQualifier, this.nameFormat), Rights.PossessProperty));
        //        }
        //    }

        //    return this.claims.AsReadOnly();
        //}

        // TODO - where / does this fit in?
        //public virtual ClaimSet ExtractSubjectKeyClaimSet(SamlSecurityTokenAuthenticator samlAuthenticator)
        //{
        //    if ((this.subjectKeyClaimset == null) && (this.securityKeyIdentifier != null))
        //    {
        //        if (samlAuthenticator == null)
        //            throw LogHelper.LogArgumentNullException(nameof(samlAuthenticator");

        //        if (this.subjectToken != null)
        //        {
        //            this.subjectKeyClaimset = samlAuthenticator.ResolveClaimSet(this.subjectToken);

        //            this.identity = samlAuthenticator.ResolveIdentity(this.subjectToken);
        //            if ((this.identity == null) && (this.subjectKeyClaimset != null))
        //            {
        //                Claim identityClaim = null;
        //                foreach (Claim claim in this.subjectKeyClaimset.FindClaims(null, Rights.Identity))
        //                {
        //                    identityClaim = claim;
        //                    break;
        //                }

        //                if (identityClaim != null)
        //                {
        //                    this.identity = SecurityUtils.CreateIdentity(identityClaim.Resource.ToString(), this.GetType().Name);
        //                }
        //            }
        //        }

        //        if (this.subjectKeyClaimset == null)
        //        {
        //            // Add the type of the primary claim as the Identity claim.
        //            this.subjectKeyClaimset = samlAuthenticator.ResolveClaimSet(this.securityKeyIdentifier);
        //            this.identity = samlAuthenticator.ResolveIdentity(this.securityKeyIdentifier);
        //        }
        //    }

        //    return this.subjectKeyClaimset;
        //}
    }
}
