//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Tokens
{
    public class SecurityKeyIdentifier// : IEnumerable<SecurityKeyIdentifierClause>
    {
        //private List<SecurityKeyIdentifierClause> clauses = new List<SecurityKeyIdentifierClause>();

        //public SecurityKeyIdentifier()
        //{
        //}

        //public SecurityKeyIdentifier(params SecurityKeyIdentifierClause[] clauses)
        //{
        //    if (clauses == null)
        //    {
        //        throw LogHelper.LogArgumentNullException(nameof(clauses));
        //    }

        //    this.clauses = new List<SecurityKeyIdentifierClause>(clauses.Length);
        //    for (int i = 0; i < clauses.Length; i++)
        //    {
        //        Add(clauses[i]);
        //    }
        //}

        //public SecurityKeyIdentifierClause this[int index]
        //{
        //    get { return this.clauses[index]; }
        //}

        //public bool CanCreateKey
        //{
        //    get
        //    {
        //        for (int i = 0; i < this.Count; i++)
        //        {
        //            if (this[i].CanCreateKey)
        //            {
        //                return true;
        //            }
        //        }
        //        return false;
        //    }
        //}

        //public int Count
        //{
        //    get { return this.clauses.Count; }
        //}

        //public void Add(SecurityKeyIdentifierClause clause)
        //{
        //    if (clause == null)
        //    {
        //        throw LogHelper.LogArgumentNullException(nameof(clause));
        //    }

        //    this.clauses.Add(clause);
        //}

        //public SecurityKey CreateKey()
        //{
        //    for (int i = 0; i < this.Count; i++)
        //    {
        //        if (this[i].CanCreateKey)
        //        {
        //            return this[i].CreateKey();
        //        }
        //    }
        //    throw LogHelper.LogExceptionMessage(new SecurityTokenException("KeyIdentifierCannotCreateKey"));
        //}

        //public TClause Find<TClause>() where TClause : SecurityKeyIdentifierClause
        //{
        //    TClause clause;
        //    if (!TryFind<TClause>(out clause))
        //    {
        //        //throw LogHelper.LogExceptionMessage(new ArgumentException(SR.GetString(SR.NoKeyIdentifierClauseFound, typeof(TClause)), "TClause"));
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("NoKeyIdentifierClauseFound"));
        //    }
        //    return clause;
        //}

        //public IEnumerator<SecurityKeyIdentifierClause> GetEnumerator()
        //{
        //    return this.clauses.GetEnumerator();
        //}

        //public bool TryFind<TClause>(out TClause clause) where TClause : SecurityKeyIdentifierClause
        //{
        //    for (int i = 0; i < this.clauses.Count; i++)
        //    {
        //        TClause c = this.clauses[i] as TClause;
        //        if (c != null)
        //        {
        //            clause = c;
        //            return true;
        //        }
        //    }
        //    clause = null;
        //    return false;
        //}

        //IEnumerator IEnumerable.GetEnumerator()
        //{
        //    return this.GetEnumerator();
        //}
    }
}

