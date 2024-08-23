// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Xunit;

namespace Microsoft.IdentityModel.Abstractions.Tests
{
    public class UnitTests
    {
        [Fact]
        public void Unit_Default()
        {
            Assert.Equal(Unit.Default, Unit.Default);
            Assert.True(Unit.Default == Unit.Default);
            Assert.Equal(Unit.Default, new Unit());
            Assert.True(new Unit() == Unit.Default);
        }
    }
}
