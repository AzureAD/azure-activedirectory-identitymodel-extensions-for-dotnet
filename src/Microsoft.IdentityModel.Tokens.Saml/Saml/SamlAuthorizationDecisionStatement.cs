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
    public class SamlAuthorizationDecisionStatement : SamlSubjectStatement
    {
        private Collection<SamlAction> _actions = new Collection<SamlAction>();
        private string _resource;

        // TODO - rewrite so this internal is not needed
        internal SamlAuthorizationDecisionStatement()
        {
        }

        public SamlAuthorizationDecisionStatement(
            SamlSubject subject,
            string resource,
            SamlAccessDecision accessDecision,
            IEnumerable<SamlAction> actions)
            : this(subject, resource, accessDecision, actions, null)
        {
        }

        public SamlAuthorizationDecisionStatement(
            SamlSubject subject,
            string resource,
            SamlAccessDecision accessDecision,
            IEnumerable<SamlAction> actions,
            SamlEvidence evidence)
            : base(subject)
        {
            if (actions == null)
                throw LogHelper.LogArgumentNullException(nameof(actions));

            foreach (var action in actions)
            {
                if (action == null)
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                _actions.Add(action);
            }

            Evidence = evidence;
            AccessDecision = accessDecision;
            _resource = resource;

            CheckObjectValidity();
        }

        public static string ClaimType
        {
            get
            {
                return ClaimTypes.AuthorizationDecision;
            }
        }

        public ICollection<SamlAction> Actions
        {
            get { return _actions; }
        }

        // TODO can this be null ???
        public SamlAccessDecision AccessDecision
        {
            get; set;
        }

        // TODO can this be null ???
        public SamlEvidence Evidence
        {
            get; set;
        }

        // TODO can this be null ???
        public string Resource
        {
            get { return _resource; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _resource = value;
            }
        }

        // TODO - how do we surface claims?
        //protected override void AddClaimsToList(IList<Claim> claims)
        //{
        //    if (claims == null)
        //        throw LogHelper.LogExceptionMessage(new ArgumentNullException("claims"));

        //    for (int i = 0; i < this.actions.Count; ++i)
        //    {
        //        claims.Add(new Claim(ClaimTypes.AuthorizationDecision, new SamlAuthorizationDecisionClaimResource(this.resource, this.accessDecision, this.actions[i].Namespace, this.actions[i].Action), Rights.PossessProperty));
        //    }
        //}

        // TODO - incorporate validation of #actions
        void CheckObjectValidity()
        {
            if (_actions.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionShouldHaveOneAction"));
        }
    }
}
