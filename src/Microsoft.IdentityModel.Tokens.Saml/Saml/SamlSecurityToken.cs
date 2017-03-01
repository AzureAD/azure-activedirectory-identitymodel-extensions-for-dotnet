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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlSecurityToken : SecurityToken
    {
        SamlAssertion _assertion;

        protected SamlSecurityToken()
        {
        }

        public SamlSecurityToken(SamlAssertion assertion)
        {
            Initialize(assertion);
        }

        protected void Initialize(SamlAssertion assertion)
        {
            if (assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            _assertion = assertion;
        }

        public override string Id
        {
            get { return _assertion.AssertionId; }
        }

        public override SecurityKey SecurityKey
        {
            get
            {
                return _assertion.SecurityKey;
            }
        }

        public SamlAssertion Assertion
        {
            get { return _assertion; }
        }

        public override DateTime ValidFrom
        {
            get
            {
                if (_assertion.Conditions != null)
                {
                    return _assertion.Conditions.NotBefore;
                }

                return SecurityUtils.MinUtcDateTime;
            }
        }

        public override DateTime ValidTo
        {
            get
            {
                if (_assertion.Conditions != null)
                {
                    return _assertion.Conditions.NotOnOrAfter;
                }

                return SecurityUtils.MaxUtcDateTime;
            }
        }

        public override string Issuer
        {
            get
            {
                return _assertion.Issuer;
            }
        }

        public override SecurityKey SigningKey
        {
            get
            {
                throw new NotImplementedException();
            }

            set
            {
                throw new NotImplementedException();
            }
        }
    }
}
