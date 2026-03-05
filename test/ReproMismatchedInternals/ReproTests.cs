using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Reproduction;

public class ReproTests
{
    [Theory]
    [InlineData("""
              { "authorization_endpoint":"https://an.example/authorize",
                "token_endpoint":"https://an.example/token" }
              """)]
    [InlineData("""
              { "token_endpoint":"https://an.example/token",
                "authorization_endpoint":"https://an.example/authorize" }
              """)]
    public async Task Can_parse_well_known(string json)
    {
        var config = await OpenIdConnectConfigurationRetriever.GetAsync
            ("-", new FakeDocumentRetriever(json), CancellationToken.None);

        Assert.Equal("https://an.example/token", config.TokenEndpoint);

        Assert.Equal("https://an.example/authorize", config.AuthorizationEndpoint);
    }

    public sealed class FakeDocumentRetriever(string json) : IDocumentRetriever
    {
        public Task<string> GetDocumentAsync
            (string address, CancellationToken cancel) =>
            Task.FromResult(json);
    }
}
