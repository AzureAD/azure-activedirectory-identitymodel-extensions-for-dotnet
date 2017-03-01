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

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information about the keys inside the tokens.
    /// </summary>
    public abstract class SecurityKeyIdentifierClause
    {
        readonly string clauseType;
        byte[] derivationNonce;
        int derivationLength;
        string id = null;

        protected SecurityKeyIdentifierClause(string clauseType)
            : this(clauseType, null, 0)
        {
        }

        protected SecurityKeyIdentifierClause(string clauseType, byte[] nonce, int length)
        {
            this.clauseType = clauseType;
            this.derivationNonce = nonce;
            this.derivationLength = length;
        }

        public virtual bool CanCreateKey
        {
            get { return false; }
        }

        public string ClauseType
        {
            get { return this.clauseType; }
        }

        public string Id
        {
            get { return this.id; }
            set { this.id = value; }
        }

        public virtual SecurityKey CreateKey()
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException("KeyIdentifierClauseDoesNotSupportKeyCreation"));
        }

        public virtual bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            return ReferenceEquals(this, keyIdentifierClause);
        }

        public byte[] GetDerivationNonce()
        {
            return (this.derivationNonce != null) ? (byte[])this.derivationNonce.Clone() : null;
        }

        public int DerivationLength
        {
            get { return this.derivationLength; }
        }
    }
}
