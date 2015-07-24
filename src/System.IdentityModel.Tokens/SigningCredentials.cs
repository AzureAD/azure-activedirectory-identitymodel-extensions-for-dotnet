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

using System;

namespace System.IdentityModel.Tokens
{
    public class SigningCredentials
    {
        string digestAlgorithm;
        string signatureAlgorithm;
        SecurityKey signingKey;
        string kid;

        public SigningCredentials(SecurityKey signingKey, string signatureAlgorithm, string digestAlgorithm) :
            this(signingKey, signatureAlgorithm, digestAlgorithm, null)
        {}

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
