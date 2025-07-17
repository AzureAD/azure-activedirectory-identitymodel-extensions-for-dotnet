// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Xunit;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class Saml2AuthenticationContextWithAppContextTests
    {
        [Fact]
        public void Saml2AuthenticationContext_RelativeClassReference_AllowRelativeUris_NoException()
        {
            try
            {
                var classRef = new Uri("resource", UriKind.Relative);
                AppContext.SetSwitch(AppContextSwitches.AllowRelativeUrisInSaml2AuthnContextSwitch, true);
                var authContext = new Saml2AuthenticationContext
                {
                    ClassReference = classRef
                };
                Assert.Equal(classRef, authContext.ClassReference);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }
        }
    }
}
