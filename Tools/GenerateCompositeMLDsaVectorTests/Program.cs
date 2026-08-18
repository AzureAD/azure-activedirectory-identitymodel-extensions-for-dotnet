// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Generates CompositeMLDsaSpecVectorTests.cs from the spec reference repository.
// Run from the repository root:
//
//   dotnet run --project tools/GenerateCompositeMLDsaVectorTests
//
// The generated file is written to:
//   test/Microsoft.IdentityModel.Tokens.Tests/CompositeMLDsaSpecVectorTests.cs

using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

string baseUrl =
    "https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-pq-composite-sigs/main/examples/jose/examples/";

(string jose, string file)[] algorithms =
[
    ("ML-DSA-44-ES256", "ML-DSA-44-ES256.jose.json"),
    ("ML-DSA-65-ES256", "ML-DSA-65-ES256.jose.json"),
    ("ML-DSA-87-ES384", "ML-DSA-87-ES384.jose.json"),
];

string outPath = args.Length > 0
    ? args[0]
    : Path.GetFullPath(
        Path.Combine(
            AppContext.BaseDirectory,
            @"..\..\..\..\..\..\test\Microsoft.IdentityModel.Tokens.Tests\CompositeMLDsaSpecVectorTests.cs"));

Console.WriteLine($"Output: {outPath}");

using var http = new HttpClient();
var sb = new StringBuilder();

WriteHeader(sb);

foreach (var (joseName, fileName) in algorithms)
{
    Console.WriteLine($"  Fetching {fileName}...");
    string json = await http.GetStringAsync(baseUrl + fileName);
    var doc = JsonNode.Parse(json)!;

    string pub  = doc["jwk"]!["pub"]!.GetValue<string>();
    string priv = doc["jwk"]!["priv"]!.GetValue<string>();
    string jws  = doc["jws"]!.GetValue<string>();

    Console.WriteLine($"    jws={jws.Length} pub={pub.Length} priv={priv.Length} pub[0]={jws[0]}");
    WriteVectorConstants(sb, joseName, pub, priv, jws);
}

WriteTestMethods(sb);
WriteFooter(sb);

File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
Console.WriteLine("Done.");

static void WriteHeader(StringBuilder sb)
{
    sb.AppendLine("// Copyright (c) Microsoft Corporation. All rights reserved.");
    sb.AppendLine("// Licensed under the MIT License.");
    sb.AppendLine("//");
    sb.AppendLine("// AUTO-GENERATED — do not edit by hand.");
    sb.AppendLine("// Regenerate with: dotnet run --project tools/GenerateCompositeMLDsaVectorTests");
    sb.AppendLine("//");
    sb.AppendLine("// Source: draft-ietf-jose-pq-composite-sigs-02 Appendix A.1");
    sb.AppendLine("// https://github.com/ietf-wg-jose/draft-ietf-jose-pq-composite-sigs/tree/main/examples/jose/examples");
    sb.AppendLine();
    sb.AppendLine("using System;");
    sb.AppendLine("using System.Text;");
    sb.AppendLine("using Microsoft.IdentityModel.TestUtils;");
    sb.AppendLine("using Microsoft.IdentityModel.Tokens;");
    sb.AppendLine("using Xunit;");
    sb.AppendLine();
    sb.AppendLine("#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental");
    sb.AppendLine();
    sb.AppendLine("namespace Microsoft.IdentityModel.Tokens.Tests;");
    sb.AppendLine();
    sb.AppendLine("public class CompositeMLDsaSpecVectorTests");
    sb.AppendLine("{");
}

static void WriteVectorConstants(StringBuilder sb, string joseName, string pub, string priv, string jws)
{
    string safe = joseName.Replace("-", "");
    sb.AppendLine("    // " + joseName + " — draft-ietf-jose-pq-composite-sigs-02 Appendix A.1");
    sb.AppendLine("    private const string " + safe + "Pub = \"" + pub + "\";");
    sb.AppendLine("    private const string " + safe + "Priv = \"" + priv + "\";");

    const int chunkSize = 100;
    sb.Append("    private const string " + safe + "Jws =");
    for (int i = 0; i < jws.Length; i += chunkSize)
    {
        int len   = Math.Min(chunkSize, jws.Length - i);
        string ch = jws.Substring(i, len);
        sb.Append(i == 0 ? " \"" + ch + "\"" : "\n        + \"" + ch + "\"");
    }
    sb.AppendLine(";");
    sb.AppendLine();
}

static void WriteTestMethods(StringBuilder sb)
{
    sb.AppendLine("    /// <summary>");
    sb.AppendLine("    /// Verifies the BCL composite combiner against the spec's Go reference implementation.");
    sb.AppendLine("    /// Uses spec -02 wire-format keys (raw x||y pub, raw EC_d priv) directly —");
    sb.AppendLine("    /// Wilson's CompositeMLDsaAdapter normalises them to the .NET pre-02 encoding on import.");
    sb.AppendLine("    /// Bypasses JsonWebTokenHandler: the spec payload is raw text, not JSON claims.");
    sb.AppendLine("    /// PASS confirms the BCL combiner construction matches the spec reference implementation.");
    sb.AppendLine("    /// </summary>");
    sb.AppendLine("    [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256, MLDSA44ES256Pub, MLDSA44ES256Jws)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256, MLDSA65ES256Pub, MLDSA65ES256Jws)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384, MLDSA87ES384Pub, MLDSA87ES384Jws)]");
    sb.AppendLine("    public void SpecVector_CombinerVerification(string alg, string specPubB64, string jws)");
    sb.AppendLine("    {");
    sb.AppendLine("        if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(alg)) return;");
    sb.AppendLine();
    sb.AppendLine("        int dot1 = jws.IndexOf('.');");
    sb.AppendLine("        int dot2 = jws.IndexOf('.', dot1 + 1);");
    sb.AppendLine("        Assert.True(dot1 > 0 && dot2 > dot1, \"Malformed JWS\");");
    sb.AppendLine();
    sb.AppendLine("        byte[] signingInput = Encoding.ASCII.GetBytes(jws.Substring(0, dot2));");
    sb.AppendLine("        byte[] signature    = Base64UrlEncoder.DecodeBytes(jws.Substring(dot2 + 1));");
    sb.AppendLine();
    sb.AppendLine("        // Import via Wilson's JWK path — adapter normalises spec -02 raw EC format to .NET format.");
    sb.AppendLine("        var jwk = new JsonWebKey { Kty = JsonWebAlgorithmsKeyTypes.Akp, Alg = alg, Pub = specPubB64 };");
    sb.AppendLine("        Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out SecurityKey key), \"JWK import failed\");");
    sb.AppendLine("        var compositeKey = Assert.IsType<CompositeMLDsaSecurityKey>(key);");
    sb.AppendLine();
    sb.AppendLine("        bool valid = compositeKey.CompositeMLDsa.VerifyData(signingInput, signature, context: null);");
    sb.AppendLine("        Assert.True(valid, string.Format(\"Spec test vector failed for {0}\", alg));");
    sb.AppendLine("    }");
    sb.AppendLine();
    sb.AppendLine("    /// <summary>");
    sb.AppendLine("    /// Verifies that spec -02 private keys (seed||EC_d_raw) can be imported via Wilson's JWK path");
    sb.AppendLine("    /// and used to sign and verify. CompositeMLDsaAdapter normalises the format on import.");
    sb.AppendLine("    /// </summary>");
    sb.AppendLine("    [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256, MLDSA44ES256Pub, MLDSA44ES256Priv, MLDSA44ES256Jws)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256, MLDSA65ES256Pub, MLDSA65ES256Priv, MLDSA65ES256Jws)]");
    sb.AppendLine("    [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384, MLDSA87ES384Pub, MLDSA87ES384Priv, MLDSA87ES384Jws)]");
    sb.AppendLine("    public void SpecVector_PrivKeyImport(string alg, string specPubB64, string specPrivB64, string jws)");
    sb.AppendLine("    {");
    sb.AppendLine("        if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(alg)) return;");
    sb.AppendLine();
    sb.AppendLine("        var jwk = new JsonWebKey { Kty = JsonWebAlgorithmsKeyTypes.Akp, Alg = alg, Pub = specPubB64, Priv = specPrivB64 };");
    sb.AppendLine("        Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out SecurityKey key), \"Private JWK import failed\");");
    sb.AppendLine("        var compositeKey = Assert.IsType<CompositeMLDsaSecurityKey>(key);");
    sb.AppendLine("        Assert.Equal(PrivateKeyStatus.Exists, compositeKey.PrivateKeyStatus);");
    sb.AppendLine();
    sb.AppendLine("        // Re-sign the spec signing input and verify with spec pub");
    sb.AppendLine("        int dot1 = jws.IndexOf('.');");
    sb.AppendLine("        int dot2 = jws.IndexOf('.', dot1 + 1);");
    sb.AppendLine("        byte[] signingInput = Encoding.ASCII.GetBytes(jws.Substring(0, dot2));");
    sb.AppendLine("        byte[] mySig = compositeKey.CompositeMLDsa.SignData(signingInput, context: null);");
    sb.AppendLine("        Assert.True(compositeKey.CompositeMLDsa.VerifyData(signingInput, mySig, context: null),");
    sb.AppendLine("            string.Format(\"Re-sign+verify failed for {0}\", alg));");
    sb.AppendLine("    }");
}

static void WriteFooter(StringBuilder sb)
{
    sb.AppendLine("}");
}
