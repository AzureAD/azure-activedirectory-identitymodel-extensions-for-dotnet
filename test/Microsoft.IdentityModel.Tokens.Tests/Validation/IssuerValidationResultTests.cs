// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class IssuerValidationResultTests
    {
        [Theory, MemberData(nameof(IssuerValdationResultsTestCases), DisableDiscoveryEnumeration = true)]
        public async Task IssuerValidatorAsyncTests(IssuerValidationResultsTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.IssuerValidatorAsyncTests", theoryData);

            try
            {
                IssuerValidationResult issuerValidationResult = await Validators.ValidateIssuerAsync(
                    theoryData.Issuer,
                    theoryData.SecurityToken,
                    theoryData.ValidationParameters,
                    new CallContext(),
                    CancellationToken.None).ConfigureAwait(false);

                if (issuerValidationResult.Exception != null)
                    theoryData.ExpectedException.ProcessException(issuerValidationResult.Exception, context);
                else
                    theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreIssuerValidationResultsEqual(
                    issuerValidationResult,
                    theoryData.IssuerValidationResult,
                    context);
            }
            catch (SecurityTokenInvalidIssuerException ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<IssuerValidationResultsTheoryData> IssuerValdationResultsTestCases
        {
            get
            {
                TheoryData<IssuerValidationResultsTheoryData> theoryData = new();

                string validIssuer = Guid.NewGuid().ToString();
                string issClaim = Guid.NewGuid().ToString();
                var validConfig = new OpenIdConnectConfiguration() { Issuer = issClaim };
                string[] validIssuers = new string[] { validIssuer };

                theoryData.Add(new IssuerValidationResultsTheoryData("NULL_Issuer")
                {
                    ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10211:"),
                    IssuerValidationResult = new IssuerValidationResult(
                        null,
                        ValidationFailureType.NullArgument,
                        new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10211,
                                LogHelper.MarkAsNonPII(null),
                                LogHelper.MarkAsNonPII(validIssuer),
                                LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(null)),
                                LogHelper.MarkAsNonPII(null)),
                            typeof(SecurityTokenInvalidIssuerException),
                            new StackFrame(true))),
                    IsValid = false,
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters()
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("NULL_ValidationParameters")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    Issuer = issClaim,
                    IssuerValidationResult = new IssuerValidationResult(
                        issClaim,
                        ValidationFailureType.NullArgument,
                        new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("validationParameters")),
                        typeof(ArgumentNullException),
                        new StackFrame(true),
                        null)),
                    IsValid = false,
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = null
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("NULL_SecurityToken")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    Issuer = issClaim,
                    IssuerValidationResult = new IssuerValidationResult(
                        issClaim,
                        ValidationFailureType.NullArgument,
                        new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("securityToken")),
                        typeof(ArgumentNullException),
                        new StackFrame(true),
                        null)),
                    IsValid = false,
                    SecurityToken = null,
                    ValidationParameters = new ValidationParameters()
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Valid_FromConfig")
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    Issuer = issClaim,
                    IssuerValidationResult = new IssuerValidationResult(
                        issClaim,
                        IssuerValidationResult.ValidationSource.IssuerIsConfigurationIssuer),
                    IsValid = true,
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters()
                    {
                        ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfig)
                    }
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Valid_FromValidationParametersValidIssuers")
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    Issuer = issClaim,
                    IssuerValidationResult = new IssuerValidationResult(
                        issClaim,
                        IssuerValidationResult.ValidationSource.IssuerIsAmongValidIssuers),
                    IsValid = true,
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters()
                    {
                        ValidIssuers = [issClaim]
                    }
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Invalid_Issuer")
                {
                    ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10212:"),
                    Issuer = issClaim,
                    IssuerValidationResult = new IssuerValidationResult(
                        issClaim,
                        ValidationFailureType.IssuerValidationFailed,
                        new ExceptionDetail(
                            new MessageDetail(
                                LogMessages.IDX10212,
                                LogHelper.MarkAsNonPII(issClaim),
                                LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validIssuers)),
                                LogHelper.MarkAsNonPII(null)),
                            typeof(SecurityTokenInvalidIssuerException),
                            new StackFrame(true))),
                    IsValid = false,
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters { ValidIssuers = [validIssuer] }
                });

                return theoryData;
            }
        }
    }

    public class IssuerValidationResultsTheoryData : TheoryDataBase
    {
        public IssuerValidationResultsTheoryData(string testId) : base(testId)
        {
        }

        public BaseConfiguration Configuration { get; set; }

        public string Issuer { get; set; }

        internal IssuerValidationResult IssuerValidationResult { get; set; }

        public bool IsValid { get; set; }

        public SecurityToken SecurityToken { get; set; }

        internal ValidationParameters ValidationParameters { get; set; }

        internal ValidationFailureType ValidationFailureType { get; set; }
    }
}
