using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class CanReadTokenTests
    {
        [Fact]
        public void CanReadUnsignedTokenWithBase64PaddingCharacters()
        {
            var encodedHeaderWithPaddingCharacters = $"{Base64UrlEncoder.Encode(@"{""typ"":""JWT""}")}==";
            var encodedHeader = Base64UrlEncoder.Encode(@"{""typ"": ""JWT""}");

            var encodedPayload = Base64UrlEncoder.Encode(@"{""iss"":""some-issuer""}");

            var handler = new JwtSecurityTokenHandler();

            Assert.True(handler.CanReadToken($"{encodedHeaderWithPaddingCharacters}.{encodedPayload}."));
            Assert.True(handler.CanReadToken($"{encodedHeader}.{encodedPayload}."));
        }
    }
}
