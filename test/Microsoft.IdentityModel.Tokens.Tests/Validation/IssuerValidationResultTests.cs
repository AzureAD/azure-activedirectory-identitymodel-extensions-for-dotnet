﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
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

            if (theoryData.ValidIssuerToAdd != null)
                theoryData.ValidationParameters.ValidIssuers.Add(theoryData.ValidIssuerToAdd);

            Result<ValidatedIssuer, ExceptionDetail> result = await Validators.ValidateIssuerAsync(
                theoryData.Issuer,
                theoryData.SecurityToken,
                theoryData.ValidationParameters,
                new CallContext(),
                CancellationToken.None).ConfigureAwait(false);

            if (result.IsSuccess)
            {
                IdentityComparer.AreValidatedIssuersEqual(
                    theoryData.Result.UnwrapResult(),
                    result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                Exception exception = result.UnwrapError().GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
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
                    Result = new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10211,
                            LogHelper.MarkAsNonPII(null),
                            LogHelper.MarkAsNonPII(validIssuer),
                            LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(null)),
                            LogHelper.MarkAsNonPII(null)),
                        ExceptionType.SecurityTokenInvalidIssuer,
                        null,
                        null),
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters()
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("NULL_ValidationParameters")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    Issuer = issClaim,
                    Result = new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("validationParameters")),
                        ExceptionType.ArgumentNull,
                        null,
                        null),
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = null
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("NULL_SecurityToken")
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    Issuer = issClaim,
                    Result = new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("securityToken")),
                        ExceptionType.ArgumentNull,
                        null,
                        null),
                    SecurityToken = null,
                    ValidationParameters = new ValidationParameters()
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Valid_FromConfig")
                {
                    Issuer = issClaim,
                    Result = new ValidatedIssuer(issClaim, IssuerValidationSource.IssuerIsConfigurationIssuer),
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters()
                    {
                        ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfig)
                    }
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Valid_FromValidationParametersValidIssuers")
                {
                    Issuer = issClaim,
                    Result = new ValidatedIssuer(issClaim, IssuerValidationSource.IssuerIsAmongValidIssuers),
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters(),
                    ValidIssuerToAdd = issClaim
                });

                theoryData.Add(new IssuerValidationResultsTheoryData("Invalid_Issuer")
                {
                    ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10212:"),
                    Issuer = issClaim,
                    Result = new ExceptionDetail(
                        new MessageDetail(
                            LogMessages.IDX10212,
                            LogHelper.MarkAsNonPII(issClaim),
                            LogHelper.MarkAsNonPII(Utility.SerializeAsSingleCommaDelimitedString(validIssuers)),
                            LogHelper.MarkAsNonPII(null)),
                        ExceptionType.SecurityTokenInvalidIssuer,
                        null,
                        null),
                    SecurityToken = JsonUtilities.CreateUnsignedJsonWebToken(JwtRegisteredClaimNames.Iss, issClaim),
                    ValidationParameters = new ValidationParameters(),
                    ValidIssuerToAdd = validIssuer
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

        internal Result<ValidatedIssuer, ExceptionDetail> Result { get; set; }

        public SecurityToken SecurityToken { get; set; }

        internal ValidationParameters ValidationParameters { get; set; }

        internal ValidationFailureType ValidationFailureType { get; set; }
        public string ValidIssuerToAdd { get; internal set; }
    }
}
