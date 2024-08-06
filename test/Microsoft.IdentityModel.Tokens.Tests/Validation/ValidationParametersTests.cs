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
            Assert.Throws<ArgumentNullException>(() => validationParameters.IssuerSigningKeyValidator = null);
        }

        [Fact]
        public void ValidTypes_Get_ReturnsValidTokenTypes()
        {
            var validationParameters = new ValidationParameters();
            var validTokenTypes = new List<string> { "JWT", "SAML" };
            validationParameters.ValidTypes = validTokenTypes;

            var result = validationParameters.ValidTypes;

            Assert.Equal(validTokenTypes, result);
        }

        [Fact]
        public void ValidTypes_Set_UpdatesValidTokenTypes()
        {
            var validationParameters = new ValidationParameters();
            var validTokenTypes = new List<string> { "JWT", "SAML" };

            validationParameters.ValidTypes = validTokenTypes;

            Assert.Equal(validTokenTypes, validationParameters.ValidTypes);
        }

        [Fact]
        public void ValidTypes_Set_Null_ThrowsArgumentNullException()
        {
            var validationParameters = new ValidationParameters();
            Assert.Throws<ArgumentNullException>(() => validationParameters.ValidTypes = null);
        }
    }
}
