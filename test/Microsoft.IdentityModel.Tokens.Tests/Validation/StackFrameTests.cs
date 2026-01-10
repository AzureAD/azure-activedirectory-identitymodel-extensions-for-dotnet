// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.TokenValidation.Tests
{
    [CollectionDefinition("StackFrameTests", DisableParallelization = true)]
    public class StackFrameTests
    {
        /// <summary>
        /// The purpose of this test is to ensure that the stack frames are cached and reused
        /// </summary>
        /// <param name="theoryData"></param>
        /// <returns></returns>
        [Theory, MemberData(nameof(StackFrameTestCases), DisableDiscoveryEnumeration = true)]
        public async Task StackFrameCount(ValidateTokenTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.StackFrameCount", theoryData);

            try
            {
                ValidationError.CachedStackFrames.Clear();

                ValidationResult<ValidatedToken, ValidationError> validationResult =
                    await theoryData.TestingTokenHandler.ValidateTokenAsync(
                        theoryData.Token,
                        theoryData.ValidationParameters,
                        theoryData.CallContext,
                        CancellationToken.None);

                int numberOfCachedStackFrames = ValidationError.CachedStackFrames.Count;

                validationResult =
                    await theoryData.TestingTokenHandler.ValidateTokenAsync(
                        theoryData.Token,
                        theoryData.ValidationParameters,
                        theoryData.CallContext,
                        CancellationToken.None);

                int numberOfKeys = theoryData.ValidationParameters.SigningKeys.Count;

                // If TryAllSigningKeys is true, we expect a StackFrame to be added to ValidationError.StackFrames for each key used in validation
                // but not added to the ValidationError.CachedStackFrames.
                // However, when adding new keys, watch out for the case where different keys result in different stack frames.
                // This test succeeds because each key failure results in the fault in the same location so the StackFrame will not be added to ValidationError.CachedStackFrames.
                // If this test starts to fail a good place to start looking is for failures resulting in a new StackFrame created.
                // Setting ValidateTokenTheoryData.IncludeInStackFrameCountTest to false may be helpful, but be careful as it may be an indication of a bug in the code under test.
                // We could have added a property in ValidationTokenTheoryData.ExpectedStackFrameCount or ValidationTokenTheoryData.StackFrameCountAdjustment
                // but experience shows these are fragile.
                int expectedValidationErrorStackFrameCount = ValidationError.CachedStackFrames.Count +
                    (theoryData.ValidationParameters.TryAllSigningKeys ? (numberOfKeys > 1 ? numberOfKeys - 1 : 0) : 0);

                // Check that ValidationError.StackFrames has the expected number of stack frames.
                if (validationResult.Error.StackFrames.Count != expectedValidationErrorStackFrameCount)
                    context.Diffs.Add(
                        $"validationResult.Error.StackFrames.Count: '{validationResult.Error.StackFrames.Count}'" +
                        $"\n!=" +
                        $"\nexpectedStackFrameCount: '{expectedValidationErrorStackFrameCount}" +
                        $"\nTokenHandler: '{theoryData.TestingTokenHandler}'" +
                        $"\nTestId: '{theoryData.TestId}.'");

                // Check that the number of CachedStackFrames has not changed from the first validation fault.
                if (numberOfCachedStackFrames != ValidationError.CachedStackFrames.Count)
                    context.Diffs.Add(
                        $"numberOfCachedStackFrames: '{numberOfCachedStackFrames}'" +
                        $"\n!=" +
                        $"\nValidationError.CachedStackFrames.Count'{ValidationError.CachedStackFrames.Count}'" +
                        $"\nTokenHandler: '{theoryData.TestingTokenHandler}'" +
                        $"\nTestId: '{theoryData.TestId}.");
            }
            catch (Exception ex)
            {
                TestUtilities.RecordUnexpectedException(context, theoryData, ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> StackFrameTestCases
        {
            get
            {
                TheoryData<ValidateTokenTheoryData> theoryData = new();

                AddInvalidTokenTestCases(theoryData, new JsonWebTestingTokenHandler());
                AddInvalidTokenTestCases(theoryData, new SamlSecurityTestingTokenHandler());
                AddInvalidTokenTestCases(theoryData, new Saml2SecurityTestingTokenHandler());

                return theoryData;
            }
        }

        private static void AddInvalidTokenTestCases(TheoryData<ValidateTokenTheoryData> theoryData, ITestingTokenHandler tokenHandler)
        {
            tokenHandler.SetDefaultTimesOnTokenCreation = false;

            AddStackFrameTests(TestCaseProvider.GenerateInvalidAlgorithmTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidAudienceTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidIssuerSigningKeyTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidIssuerTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidLifetimeTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidReadTokenTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidSignatureTestCases(tokenHandler), theoryData);
            AddStackFrameTests(TestCaseProvider.GenerateInvalidTokenReplayTestCases(tokenHandler), theoryData);
        }

        private static void AddStackFrameTests(
            TheoryData<ValidateTokenTheoryData> theoryDataSource,
            TheoryData<ValidateTokenTheoryData> theoryDataTarget)
        {
            foreach (var test in theoryDataSource)
            {
                if (!test.IncludeInStackFrameCountTest)
                    continue;

                theoryDataTarget.Add(test);
            }
        }
    }
}
