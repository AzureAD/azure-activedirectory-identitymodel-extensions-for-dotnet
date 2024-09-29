// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.TestUtils
{
    internal class MockTimeProvider : TimeProvider
    {
        // always return 09/16/2024 00:00:00:00
        public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2024, 9, 16, 0, 0, 0, new(0));
    }
}
