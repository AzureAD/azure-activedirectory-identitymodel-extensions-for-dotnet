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

using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.Reflection;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectProtocolValidationContextTests
    {
        [Fact(DisplayName = "OpenIdConnectProtocolValidationContextTests: GetSets, test covers defaults")]
        public void GetSets()
        {
            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();
            Type type = typeof(OpenIdConnectProtocolValidationContext);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 2)
                Assert.True(true, "Number of properties has changed from 2 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>> 
                    { 
                        new KeyValuePair<string, List<object>>("AuthorizationCode", new List<object>{(string)null, "AuthorizationCode", "AuthorizationCode_AuthorizationCode"}),
                        new KeyValuePair<string, List<object>>("Nonce", new List<object>{(string)null, "Nonce", "Nonce_Nonce"}),                            
                    },
                    Object = validationContext,
                };
            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectProtocolValidationContext_GetSets", context.Errors);
        }
    }
}