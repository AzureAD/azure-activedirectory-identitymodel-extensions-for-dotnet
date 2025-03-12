// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>
    /// Represents the Cnf Claim
    /// </summary>
    internal class Cnf : Tokens.Cnf
    {
        private readonly string _shrClassName = "Microsoft.IdentityModel.Protocols.SignedHttpRequest.Cnf";

        public Cnf() : base()
        {
            ClassName = _shrClassName;
        }

        public Cnf(string json) : base(json)
        {
            ClassName = _shrClassName;
        }
    }
}
