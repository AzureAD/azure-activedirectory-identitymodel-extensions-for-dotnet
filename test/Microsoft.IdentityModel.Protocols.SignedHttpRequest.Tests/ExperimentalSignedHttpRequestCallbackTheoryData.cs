// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;
using Context = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationContext;
using Policy = Microsoft.IdentityModel.Protocols.SignedHttpRequest.SignedHttpRequestValidationParameters;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public partial class ExperimentalSignedHttpRequestPipelineTests
    {
        public enum CallbackOutcome
        {
            Success, Error, Throw, Default, NullTask, Cancel, CancelThenReturn, UnrequestedCancellation, NullResult
        }

        public class ExperimentalCallbackTheoryData : TheoryDataBase
        {
            public ExperimentalCallbackTheoryData(string testId) : base(testId) { }
            public CallbackOutcome Outcome { get; set; }
            public SignedHttpRequestValidationFailure Stage { get; set; }
            public Action<CallbackFixture> Configure { get; set; }
            public override string ToString() => TestId;
        }

        public class CallbackFixture
        {
            private readonly CallbackOutcome _outcome;
            private readonly CancellationTokenSource _cancellation;
            internal readonly ValidationError NestedError = ValidationError.NullParameter("callback-sentinel", ValidationError.GetCurrentStackFrame());
            internal readonly Exception ThrownException = new InvalidOperationException("extension-sentinel");
            internal readonly SecurityKey Key = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            internal readonly JObject Payload = ExperimentalSignedHttpRequestPipelineTests.Payload();
            internal readonly Policy Policy = AllClaims();
            internal readonly ValidationParameters Parameters = ExperimentalSignedHttpRequestPipelineTests.Parameters();
            internal Context Context;
            internal SigningCredentials SigningCredentials;
            internal int Calls;

            internal CallbackFixture(CallbackOutcome outcome, CancellationTokenSource cancellation)
            {
                _outcome = outcome;
                _cancellation = cancellation;
            }

            internal Task<ValidationResult<T, ValidationError>> Result<T>(T value)
            {
                Calls++;
                return CallbackResult(_outcome, value, NestedError, ThrownException, _cancellation);
            }

            internal void ConfigurePopKeyResolver()
            {
                var resolver = new Mock<IPopKeyResolver>(MockBehavior.Strict);
                resolver.Setup(x => x.ResolvePopKeyAsync(It.IsAny<SecurityToken>(), It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result(Key));
                Policy.PopKeyResolver = resolver.Object;
            }

            internal void ConfigureKeyIdResolver()
            {
                Payload["at"] = AccessToken(SignedHttpRequestTestUtils.DefaultKid);
                var resolver = new Mock<IPopKeyResolverFromKeyId>(MockBehavior.Strict);
                resolver.Setup(x => x.ResolvePopKeyFromKeyIdAsync(KeyingMaterial.RsaSecurityKey_2048.KeyId,
                    It.IsAny<SecurityToken>(), It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result(Key));
                Policy.PopKeyResolverFromKeyId = resolver.Object;
            }

            internal void ConfigureDecryptionKeysResolver()
            {
                Payload["at"] = AccessToken(SignedHttpRequestTestUtils.DefaultCnfJwe);
                SigningCredentials = SymmetricCredentials();
                var resolver = new Mock<ICnfDecryptionKeysResolver>(MockBehavior.Strict);
                resolver.Setup(x => x.ResolveDecryptionKeysAsync(It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result<IList<SecurityKey>>(new List<SecurityKey> { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }));
                Policy.CnfDecryptionKeysResolver = resolver.Object;
            }

            internal void ConfigureSignatureValidator()
            {
                var validator = new Mock<ISignedHttpRequestSignatureValidator>(MockBehavior.Strict);
                validator.Setup(x => x.ValidateSignatureAsync(It.IsAny<SecurityKey>(), It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result(Key));
                Policy.SignatureValidator = validator.Object;
            }

            internal void ConfigureNonceValidator()
            {
                var validator = new Mock<INonceValidator>(MockBehavior.Strict);
                validator.Setup(x => x.ValidateNonceAsync(It.IsAny<SecurityKey>(), It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result(true));
                Policy.NonceValidator = validator.Object;
            }

            internal void ConfigureReplayValidator()
            {
                var validator = new Mock<IReplayValidator>(MockBehavior.Strict);
                validator.Setup(x => x.ValidateReplayAsync(It.IsAny<SecurityToken>(),
                    It.Is<Context>(c => ReferenceEquals(c, Context)), _cancellation.Token))
                    .Returns(() => Result(true));
                Policy.ReplayValidator = validator.Object;
            }

            internal void ConfigureAccessTokenHandler()
            {
                Policy.TokenHandler = new RecordingTokenHandler
                {
                    OnValidate = async (token, parameters, callContext, cancellationToken) =>
                    {
                        Assert.Same(Parameters, parameters);
                        Assert.Same(Context.CallContext, callContext);
                        Assert.Equal(_cancellation.Token, cancellationToken);
                        var valid = await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters, callContext, cancellationToken);
                        Assert.True(valid.Succeeded, valid.Error?.Message);
                        return await Result(valid.Result);
                    }
                };
            }
        }

        public static TheoryData<ExperimentalCallbackTheoryData> CallbackCases
        {
            get
            {
                var data = new TheoryData<ExperimentalCallbackTheoryData>();
                AddCallbackCases(data, "PopKeyResolver", SignedHttpRequestValidationFailure.PopKey, f => f.ConfigurePopKeyResolver());
                AddCallbackCases(data, "KeyIdResolver", SignedHttpRequestValidationFailure.PopKey, f => f.ConfigureKeyIdResolver());
                AddCallbackCases(data, "DecryptionKeysResolver", SignedHttpRequestValidationFailure.PopKey, f => f.ConfigureDecryptionKeysResolver());
                AddCallbackCases(data, "SignatureValidator", SignedHttpRequestValidationFailure.Signature, f => f.ConfigureSignatureValidator());
                AddCallbackCases(data, "NonceValidator", SignedHttpRequestValidationFailure.Nonce, f => f.ConfigureNonceValidator(), false);
                AddCallbackCases(data, "ReplayValidator", SignedHttpRequestValidationFailure.Replay, f => f.ConfigureReplayValidator(), false);
                AddCallbackCases(data, "AccessTokenHandler", SignedHttpRequestValidationFailure.AccessToken, f => f.ConfigureAccessTokenHandler());
                return data;
            }
        }

        private static void AddCallbackCases(TheoryData<ExperimentalCallbackTheoryData> data, string name,
            SignedHttpRequestValidationFailure stage, Action<CallbackFixture> configure, bool referenceResult = true)
        {
            foreach (CallbackOutcome outcome in Enum.GetValues(typeof(CallbackOutcome)))
            {
                if (!referenceResult && outcome == CallbackOutcome.NullResult)
                    continue;

                data.Add(new ExperimentalCallbackTheoryData(name + "_" + outcome)
                {
                    Outcome = outcome,
                    Stage = stage,
                    Configure = configure
                });
            }
        }
    }
}
