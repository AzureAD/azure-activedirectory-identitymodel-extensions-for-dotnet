using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Tests
{
    public class TestTheoryData
    {
        public static TheoryData<TokenReplayTheoryData> TokenReplayValidationTheoryData
        {
            get
            {
                return new TheoryData<TokenReplayTheoryData>
                {
                    new TokenReplayTheoryData
                    {
                        TestId = "ValidateTokenReplay: false, TokenReplayValidator: null",
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorReturnsTrue)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsTrue
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorReturnsFalse)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsFalse
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: false, {nameof(ValidationDelegates.TokenReplayValidatorThrows)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorThrows
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: true, TokenReplayValidator: null",
                        ValidateTokenReplay = true
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorReturnsTrue)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsTrue,
                        ValidateTokenReplay = true
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorReturnsFalse)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorReturnsFalse,
                        ValidateTokenReplay = true,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("IDX10228:")
                    },
                    new TokenReplayTheoryData
                    {
                        TestId = $"ValidateTokenReplay: true, {nameof(ValidationDelegates.TokenReplayValidatorThrows)}",
                        TokenReplayValidator = ValidationDelegates.TokenReplayValidatorThrows,
                        ValidateTokenReplay = true,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetected("TokenReplayValidatorThrows")
                    }
                };
            }
        }
    }

    public class TokenReplayTheoryData : TheoryDataBase
    {
        public TokenReplayValidator TokenReplayValidator
        {
            get;
            set;
        } = null;
        public bool ValidateTokenReplay
        {
            get;
            set;
        } = false;
    }
}
