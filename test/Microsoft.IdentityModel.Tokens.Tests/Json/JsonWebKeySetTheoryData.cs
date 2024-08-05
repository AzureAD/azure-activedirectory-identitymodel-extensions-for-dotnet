// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.Tokens.Json.Tests
{
    public class JsonWebKeySetTheoryData : TheoryDataBase
    {
        public JsonWebKeySetTheoryData() { }

        public JsonWebKeySetTheoryData(string testId) : base(testId) { }

        public IList<SecurityKey> ExpectedSigningKeys { get; set; }

        public string Json { get; set; } = string.Empty;

        public JsonWebKeySet JsonWebKeySet { get; set; }
    }
}
