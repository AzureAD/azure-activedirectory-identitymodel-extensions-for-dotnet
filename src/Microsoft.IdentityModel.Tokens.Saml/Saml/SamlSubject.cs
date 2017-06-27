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
using System.Security.Claims;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Represents the Subject element specified in [Saml2Core, 2.4.2.1].
    /// </summary>
    /// <remarks>
    /// If the NameId is null and the SubjectConfirmations collection is empty,
    /// an InvalidOperationException will be thrown during serialization.
    /// </remarks>
    public class SamlSubject
    {
        // Saml SubjectConfirmation parts.
        private string _confirmationData;
        private SecurityKey _securityKey;
        private KeyInfo _keyInfo;

        // TODO remove this internal
        /// <summary>
        /// Initialize an instance of <see cref="SamlSubject"/>.
        /// </summary>
        public SamlSubject()
        {
            ConfirmationMethods = new List<string>();
        }

        /// <summary>
        /// Initialize an instance of <see cref="SamlSubject"/>.
        /// </summary>
        /// <param name="nameFormat">The format of the subject.</param>
        /// <param name="nameQualifier">The NameIdentifier of the subject.</param>
        /// <param name="name">The name of the subject.</param>
        public SamlSubject(string nameFormat, string nameQualifier, string name)
            : this(nameFormat, nameQualifier, name, null, null)
        {
        }

        /// <summary>
        /// Initialize an instance of <see cref="SamlSubject"/>.
        /// </summary>
        /// <param name="nameFormat">The format of the subject.</param>
        /// <param name="nameQualifier">The NameIdentifier of the subject.</param>
        /// <param name="name">The name of the subject.</param>
        /// <param name="confirmations"><see cref="IEnumerable{String}"/>.</param>
        /// <param name="confirmationData">The confirmation data contained in the subject.</param>
        public SamlSubject(
            string nameFormat,
            string nameQualifier,
            string name,
            IEnumerable<string> confirmations,
            string confirmationData)
        {
            if (confirmations != null)
                ConfirmationMethods = new List<string>(confirmations);

            Name = name;
            NameFormat = nameFormat;
            NameQualifier = nameQualifier;
            _confirmationData = confirmationData;
        }

        /// <summary>
        /// Gets or sets confirmation data.
        /// </summary>
        public string ConfirmationData
        {
            get
            {
                return _confirmationData;
            }
            set
            {
                _confirmationData = (!string.IsNullOrEmpty(value)) ? value : throw LogArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Gets confirmation methods.
        /// </summary>
        public ICollection<string> ConfirmationMethods { get; }

        // TODO - surface here or from assertion / token
        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/>.
        /// </summary>
        public SecurityKey Key
        {
            get { return _securityKey; }
            set
            {
                _securityKey = value ?? throw LogArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Gets or sets the<see cref="KeyInfo"/>.
        /// </summary>
        public KeyInfo KeyInfo
        {
            get { return _keyInfo; }
            set
            {
                _keyInfo = value ?? throw LogArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Gets or sets the name of the Subject.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets the ClaimType.
        /// </summary>
        public static string NameClaimType
        {
            get
            {
                return ClaimTypes.NameIdentifier;
            }
        }

        // TODO - can this be null
        /// <summary>
        /// Gets or sets the format of the Subject.
        /// </summary>
        public string NameFormat
        {
            get; set;
        }

        // TODO - can this be null
        /// <summary>
        /// Gets or sets the name qualifier of the Subject.
        /// </summary>
        public string NameQualifier
        {
            get; set;
        }

        void CheckObjectValidity()
        {
            if ((ConfirmationMethods.Count == 0) && (string.IsNullOrEmpty(Name)))
                throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11107));

            if ((ConfirmationMethods.Count == 0) && (_confirmationData != null))
                throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11510));
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
