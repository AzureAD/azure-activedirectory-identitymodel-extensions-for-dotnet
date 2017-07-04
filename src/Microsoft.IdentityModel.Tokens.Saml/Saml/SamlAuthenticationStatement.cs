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
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Represents the AttributeStatement element.
    /// </summary>
    public class SamlAuthenticationStatement : SamlSubjectStatement
    {
        private DateTime _authenticationInstant = DateTime.UtcNow.ToUniversalTime();
        private string _authenticationMethod = SamlConstants.UnspecifiedAuthenticationMethod;

        internal SamlAuthenticationStatement()
        {
            AuthorityBindings = new List<SamlAuthorityBinding>();
        }

        /// <summary>
        /// Creates an instance of <see cref="SamlAuthenticationStatement"/>.
        /// </summary>
        /// <param name="samlSubject">The Subject of the Statement.</param>
        /// <param name="authenticationMethod">The URI reference that specifies the type of authentication that took place.</param>
        /// <param name="authenticationInstant">The time at which the authentication took place.</param>
        /// <param name="dnsAddress">The DNS domain name for the system entity from which the subject was apparently authenticated.</param>
        /// <param name="ipAddress">The IP address for the system entity from which the subject was apparently authenticated.</param>
        /// <param name="authorityBindings"><see cref="IEnumerable{SamlAuthorityBinding}"/>.</param>
        public SamlAuthenticationStatement(
            SamlSubject samlSubject,
            string authenticationMethod,
            DateTime authenticationInstant,
            string dnsAddress,
            string ipAddress,
            IEnumerable<SamlAuthorityBinding> authorityBindings)
        {
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogArgumentNullException(nameof(authenticationMethod));

            AuthenticationMethod = authenticationMethod;
            AuthenticationInstant = authenticationInstant.ToUniversalTime();
            DnsAddress = dnsAddress;
            IPAddress = ipAddress;
            Subject = samlSubject;

            AuthorityBindings = (authorityBindings == null) ? new List<SamlAuthorityBinding>() : new List<SamlAuthorityBinding>(authorityBindings);
        }

        /// <summary>
        /// Gets or sets the instant of authentication.
        /// </summary>
        public DateTime AuthenticationInstant
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the method of authentication.
        /// </summary>
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

        /// <summary>
        /// Gets a collection of <see cref="ICollection{SamlAuthorityBinding}"/>.
        /// </summary>
        public ICollection<SamlAuthorityBinding> AuthorityBindings
        {
            get;
        }

        /// <summary>
        /// Gets ClaimType.
        /// </summary>
        // TODO what is this for?
        public static string ClaimType
        {
            get {return System.Security.Claims.ClaimTypes.Authentication; }
        }

        // TODO - allow null?
        /// <summary>
        /// Gets or sets Domain Name Service.
        /// </summary>
        public string DnsAddress { get; set; }

        // TODO - allow null?
        /// <summary>
        /// Gets or sets Internet Protocol.
        /// </summary>
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
