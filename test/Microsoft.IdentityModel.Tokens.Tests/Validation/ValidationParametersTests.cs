// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests.Validation
{
    public class ValidationParametersTests
    {
        [Fact]
        public void SetValidators_NullValue_ThrowsArgumentNullException()
        {
            var validationParameters = new ValidationParameters();
            Assert.Throws<ArgumentNullException>(() => validationParameters.IssuerValidatorAsync = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.TokenReplayValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.LifetimeValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.TypeValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.AudienceValidator = null);
        }

        [Fact]
        public void ValidAudiences_Get_ReturnsEmptyList()
        {
            var validationParameters = new ValidationParameters();

            Assert.Equal(0, validationParameters.ValidAudiences.Count);
            Assert.True(validationParameters.ValidAudiences is IList<string>);
        }

        [Fact]
        public void ValidTypes_Get_ReturnsEmptyList()
        {
            var validationParameters = new ValidationParameters();
            Assert.Equal(0, validationParameters.ValidTypes.Count);
            Assert.True(validationParameters.ValidTypes is IList<string>);
        }
    }
}
