//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.IdentityModel;

    public class SigningCredentials
    {
        string digestAlgorithm;
        string signatureAlgorithm;
        SecurityKey signingKey;
        string kid;

        public SigningCredentials(SecurityKey signingKey, string signatureAlgorithm, string digestAlgorithm) :
            this(signingKey, signatureAlgorithm, digestAlgorithm, null)
        { }

        public SigningCredentials(SecurityKey signingKey, string signatureAlgorithm, string digestAlgorithm, string kid)
        {
            if (signingKey == null)
            {
                throw new ArgumentNullException("signingKey");
            }

            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException("signatureAlgorithm");
            }

           
            this.signingKey = signingKey;
            this.signatureAlgorithm = signatureAlgorithm;
            this.digestAlgorithm = digestAlgorithm;
            this.kid = kid;
        }

        public string DigestAlgorithm
        {
            get { return this.digestAlgorithm; }
        }

        public string SignatureAlgorithm
        {
            get { return this.signatureAlgorithm; }
        }

        public SecurityKey SigningKey
        {
            get { return this.signingKey; }
        }

        public string Kid
        {
            get { return this.kid; }
        }
    }
}
