// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.JsonWebTokens.Results;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidateSignatureTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerValidateSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public void ValidateSignature(JsonWebTokenHandlerValidateSignatureTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ValidateSignature", theoryData);

            SignatureValidationResult validationResult = JsonWebTokenHandler.ValidateSignature(
                theoryData.JWT,
                theoryData.ValidationParameters,
                theoryData.Configuration,
                new CallContext());

            if (validationResult.Exception != null)
                theoryData.ExpectedException.ProcessException(validationResult.Exception);
            else
                theoryData.ExpectedException?.ProcessNoException();

            IdentityComparer.AreSignatureValidationResultsEqual(validationResult, theoryData.SignatureValidationResult, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebTokenHandlerValidateSignatureTheoryData> JsonWebTokenHandlerValidateSignatureTestCases
        {
            get
            {
                return new TheoryData<JsonWebTokenHandlerValidateSignatureTheoryData>
                {
                    new JsonWebTokenHandlerValidateSignatureTheoryData {

                    }
                };
            }
        }
    }

    public class JsonWebTokenHandlerValidateSignatureTheoryData : TheoryDataBase
    {
        public JsonWebToken JWT { get; set; }
        public BaseConfiguration Configuration { get; set; }
        internal SignatureValidationResult SignatureValidationResult { get; set; }
        internal ValidationParameters ValidationParameters { get; set; }
    }
}
