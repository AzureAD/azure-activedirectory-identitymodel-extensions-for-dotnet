// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class KeyWrapTheoryData : TheoryDataBase
    {
        public byte[] KeyToWrap { get; set; }

        public KeyWrapProvider Provider { get; set; }

        public string UnwrapAlgorithm { get; set; }

        public SecurityKey UnwrapKey { get; set; }

        public bool WillUnwrap { get; set; }

        public string WrapAlgorithm { get; set; }

        public SecurityKey WrapKey { get; set; }

        public byte[] WrappedKey { get; set; }
    }
}
