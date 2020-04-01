using Microsoft.IdentityModel.Protocols.WsTrust;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    /// <summary>
    /// Class used to store settings a mock channel should use when generating mock responses.
    /// </summary>
    public class MockResponseSettings
    {
        public Entropy Entropy { get; set; }

        public int? KeySizeInBits { get; set; }

        public string KeyType { get; set; }

        public Lifetime Lifetime { get; set; }

        public RequestedProofToken ProofToken { get; set; }
    }
}
