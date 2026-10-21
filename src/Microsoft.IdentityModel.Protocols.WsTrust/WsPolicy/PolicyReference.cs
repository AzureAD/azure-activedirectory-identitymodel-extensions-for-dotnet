// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Defines the wsp:PolicyReference element.
    /// </summary>
    internal class PolicyReference
    {
        public PolicyReference()
        {
        }

        public PolicyReference(string uri, string digest, string digestAlgorithm)
        {
            Uri = uri;
            Digest = digest;
            DigestAlgorithm = digestAlgorithm;
        }

        public string Digest { get; set; }

        public string DigestAlgorithm { get; set; }


        public string Uri { get; set; }
    }
}
