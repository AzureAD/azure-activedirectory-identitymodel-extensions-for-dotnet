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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlAuthenticationStatement : SamlSubjectStatement
    {
        private DateTime _authenticationInstant = DateTime.UtcNow.ToUniversalTime();
        private string _authenticationMethod = SamlConstants.UnspecifiedAuthenticationMethod;
        private Collection<SamlAuthorityBinding> _authorityBindings = new Collection<SamlAuthorityBinding>();

        internal SamlAuthenticationStatement()
        {
        }

        public SamlAuthenticationStatement(
            SamlSubject samlSubject,
            string authenticationMethod,
            DateTime authenticationInstant,
            string dnsAddress,
            string ipAddress,
            IEnumerable<SamlAuthorityBinding> authorityBindings)
            : base(samlSubject)
        {
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogHelper.LogArgumentNullException(nameof(authenticationMethod));

            AuthenticationMethod = authenticationMethod;
            AuthenticationInstant = authenticationInstant.ToUniversalTime();
            DnsAddress = dnsAddress;
            IPAddress = ipAddress;

            if (authorityBindings != null)
            {
                foreach (var binding in authorityBindings)
                {
                    if (binding == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                    _authorityBindings.Add(binding);
                }
            }
        }

        public DateTime AuthenticationInstant
        {
            get; set;
        }

        public string AuthenticationMethod
        {
            get { return _authenticationMethod; }
            set
            {
                // TODO - why are we guessing what the user set??? throw????
                if (string.IsNullOrEmpty(value))
                    _authenticationMethod = SamlConstants.UnspecifiedAuthenticationMethod;
                else
                    _authenticationMethod = value;
            }
        }

        // TODO what is this for?
        public static string ClaimType
        {
            get {return System.Security.Claims.ClaimTypes.Authentication; }
        }

        public ICollection<SamlAuthorityBinding> AuthorityBindings
        {
            get { return _authorityBindings; }
        }

        // TODO - allow null?
        public string DnsAddress { get; set; }

        // TODO - allow null?
        public string IPAddress { get; set; }

        // TODO - how to service claims
        //protected override void AddClaimsToList(IList<Claim> claims)
        //{
        //    if (claims == null)
        //        throw LogHelper.LogArgumentNullException(nameof(claims");

        //    claims.Add(new Claim(ClaimTypes.Authentication, new SamlAuthenticationClaimResource(this.authenticationInstant, this.authenticationMethod, this.dnsAddress, this.ipAddress, this.authorityBindings), Rights.PossessProperty));
        //}
    }
}
