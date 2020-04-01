using System.ServiceModel.Federation.Tests.Mocks;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class ProofTokenGenerationTheoryData : TheoryDataBase
    {
        public Entropy RequestEntropy { get; set; }

        public int? RequestKeySize { get; set; }

        public MockResponseSettings ResponseSettings { get; set; }

        public byte[] ExpectedProofKey { get; set; }
    }
}
