using System.IdentityModel.Tokens;
using System.ServiceModel.Federation.Tests.Mocks;
using System.ServiceModel.Security;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class ProofTokenGenerationTheoryData : TheoryDataBase
    {
        public SecurityAlgorithmSuite RequestSecurityAlgorithmSuite { get; set; }

        public Entropy RequestEntropy { get; set; }

        public SecurityKeyType RequestKeyType { get; set; } = SecurityKeyType.SymmetricKey;

        public int? RequestKeySize { get; set; }

        public MockResponseSettings ResponseSettings { get; set; }

        public byte[] ExpectedProofKey { get; set; }
    }
}
