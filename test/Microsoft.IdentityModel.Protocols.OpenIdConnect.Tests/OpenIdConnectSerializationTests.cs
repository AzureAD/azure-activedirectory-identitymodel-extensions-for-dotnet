// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectSerializationTests
    {
        [Theory, MemberData(nameof(SerializationMixedCaseTheoryData))]
        public void SerializationMixedCase(OpenIdConnectTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SerializationMixedCase", theoryData);

            try
            {
                OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration(theoryData.Json);
                OpenIdConnectConfiguration configurationMixedCase = new OpenIdConnectConfiguration(theoryData.JsonMixedCase);

                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(configuration, configurationMixedCase, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<OpenIdConnectTheoryData> SerializationMixedCaseTheoryData
        {
            get
            {
                TheoryData<OpenIdConnectTheoryData> theoryData = new TheoryData<OpenIdConnectTheoryData>();
                theoryData.Add(new OpenIdConnectTheoryData("MixedCaseNames")
                {
                    Json = OpenIdConfigData.LowerCaseNames,
                    JsonMixedCase = OpenIdConfigData.MixedCaseNames
                });

                theoryData.Add(new OpenIdConnectTheoryData("MixedCaseFrontChannelStringFalse")
                {
                    Json = OpenIdConfigData.LowerCaseFrontChannelStringFalse,
                    JsonMixedCase = OpenIdConfigData.MixedCaseFrontChannelStringFalse
                }); 

                theoryData.Add(new OpenIdConnectTheoryData("MixedCaseFrontChannelStringTrue")
                {
                    Json = OpenIdConfigData.LowerCaseFrontChannelStringTrue,
                    JsonMixedCase = OpenIdConfigData.MixedCaseFrontChannelStringTrue
                }); 

                return theoryData;
            }
        }
    }
}
