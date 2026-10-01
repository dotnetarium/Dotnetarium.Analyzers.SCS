using System.Collections.Immutable;
using Dotnetarium.Analyzers.Cryptography;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CryptographyTests
{
    [Theory]
    [InlineData("_ = DES.Create();", "DNA0013")]
    [InlineData("_ = TripleDES.Create();", "DNA0013")]
    [InlineData("_ = RC2.Create();", "DNA0013")]
    [InlineData("using var aes = Aes.Create(); aes.Mode = CipherMode.ECB;", "DNA0014")]
    [InlineData("using var aes = Aes.Create(); aes.EncryptEcb(new byte[16], PaddingMode.PKCS7);", "DNA0014")]
    [InlineData("using var aes = Aes.Create(); aes.CreateEncryptor(new byte[32], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = Aes.Create(); aes.IV = new byte[16]; aes.CreateEncryptor();", "DNA0015")]
    [InlineData("using var aes = Aes.Create(); var iv = new byte[16]; aes.CreateEncryptor(new byte[32], iv);", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); aes.Encrypt(new byte[12], new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new AesCcm(new byte[32]); aes.Encrypt(new byte[12], new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new ChaCha20Poly1305(new byte[32]); aes.Encrypt(new byte[12], new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("_ = Rfc2898DeriveBytes.Pbkdf2(\"p\", new byte[16], 1000, HashAlgorithmName.SHA256, 32);", "DNA0016")]
    [InlineData("_ = new Rfc2898DeriveBytes(\"p\", new byte[16], 1000, HashAlgorithmName.SHA256);", "DNA0016")]
    [InlineData("_ = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(\"p\", new byte[16], Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivationPrf.HMACSHA256, 1000, 32);", "DNA0016")]
    [InlineData("new Microsoft.AspNetCore.Identity.PasswordHasherOptions().IterationCount = 1000;", "DNA0016")]
    [InlineData("using var k = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, new byte[2400]);", "DNA0017")]
    [InlineData("using var k = MLKem.ImportFromPem(\"-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----\");", "DNA0017")]
    [InlineData("using var k = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, new byte[32]);", "DNA0017")]
    [InlineData("using var k = SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaSha2_128s, new byte[64]);", "DNA0017")]
    [InlineData("_ = Org.BouncyCastle.Security.CipherUtilities.GetCipher(\"AES/ECB/PKCS7Padding\");", "DNA0014")]
    [InlineData("_ = Org.BouncyCastle.Security.CipherUtilities.GetCipher(\"DES/CBC/PKCS7Padding\");", "DNA0013")]
    [InlineData("_ = new Org.BouncyCastle.Crypto.Engines.DesEngine();", "DNA0013")]
    [InlineData("var c = new Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()); c.Init(true, new Org.BouncyCastle.Crypto.Parameters.AeadParameters(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[16]), 128, new byte[12]));", "DNA0015")]
    [InlineData("var c = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()); c.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[16]), new byte[16]));", "DNA0015")]
    [InlineData("var c = new Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()); var p = new Org.BouncyCastle.Crypto.Parameters.AeadParameters(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[16]), 128, new byte[12]); c.Init(true, p);", "DNA0015")]
    [InlineData("using var key = NSec.Cryptography.Key.Create(NSec.Cryptography.AeadAlgorithm.Aes256Gcm); _ = NSec.Cryptography.AeadAlgorithm.Aes256Gcm.Encrypt(key, new byte[12], new byte[0], new byte[1]);", "DNA0015")]
    [InlineData("_ = Sodium.SecretBox.Create(new byte[1], new byte[24], Sodium.SecretBox.GenerateKey());", "DNA0015")]
    [InlineData("_ = Sodium.SecretBox.CreateDetached(new byte[1], new byte[24], Sodium.SecretBox.GenerateKey());", "DNA0015")]
    [InlineData("_ = Sodium.SecretAeadAes.Encrypt(new byte[1], new byte[12], Sodium.SecretBox.GenerateKey(), null);", "DNA0015")]
    [InlineData("_ = Sodium.SecretAeadChaCha20Poly1305.Encrypt(new byte[1], new byte[8], Sodium.SecretBox.GenerateKey(), null);", "DNA0015")]
    [InlineData("_ = Sodium.SecretAeadChaCha20Poly1305IETF.Encrypt(new byte[1], new byte[12], Sodium.SecretBox.GenerateKey(), null);", "DNA0015")]
    [InlineData("_ = Sodium.SecretAeadXChaCha20Poly1305.Encrypt(new byte[1], new byte[24], Sodium.SecretBox.GenerateKey(), null);", "DNA0015")]
    public async Task Reports_unsafe_cryptography(string statement, string rule)
    {
        var findings = await AnalyzeAsync(statement);
        Assert.Contains(findings, finding => finding.Id == rule);
    }

    [Theory]
    [InlineData("using var aes = Aes.Create(); aes.Mode = CipherMode.CBC;", "DNA0014")]
    [InlineData("using var aes = Aes.Create(); aes.CreateDecryptor(new byte[32], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = Aes.Create(); aes.IV = new byte[16]; aes.IV = nonce; aes.CreateEncryptor();", "DNA0015")]
    [InlineData("using var aes = Aes.Create(); aes.IV = new byte[16]; aes.GenerateIV(); aes.CreateEncryptor();", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); var n = new byte[12]; n = nonce; aes.Encrypt(n, new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); var n = new byte[12]; RandomNumberGenerator.Fill(n); aes.Encrypt(n, new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); var n = new byte[12]; n[0] = (byte)System.Environment.TickCount; aes.Encrypt(n, new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); aes.Encrypt(nonce, new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("using var aes = new AesGcm(new byte[32], 16); aes.Encrypt(RandomNumberGenerator.GetBytes(12), new byte[1], new byte[1], new byte[16]);", "DNA0015")]
    [InlineData("_ = Rfc2898DeriveBytes.Pbkdf2(\"p\", new byte[16], 600000, HashAlgorithmName.SHA256, 32);", "DNA0016")]
    [InlineData("using var k = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, new byte[1184]);", "DNA0017")]
    [InlineData("var c = new Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()); c.Init(false, new Org.BouncyCastle.Crypto.Parameters.AeadParameters(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[16]), 128, new byte[12]));", "DNA0015")]
    [InlineData("using var key = NSec.Cryptography.Key.Create(NSec.Cryptography.AeadAlgorithm.Aes256Gcm); _ = NSec.Cryptography.AeadAlgorithm.Aes256Gcm.Encrypt(key, nonce, new byte[0], new byte[1]);", "DNA0015")]
    [InlineData("_ = Sodium.SecretBox.Open(new byte[1], new byte[24], Sodium.SecretBox.GenerateKey());", "DNA0015")]
    [InlineData("_ = Sodium.SecretBox.Create(new byte[1], Sodium.SecretBox.GenerateNonce(), Sodium.SecretBox.GenerateKey());", "DNA0015")]
    [InlineData("_ = Sodium.SecretAeadXChaCha20Poly1305.Encrypt(new byte[1], Sodium.SecretAeadXChaCha20Poly1305.GenerateNonce(), Sodium.SecretBox.GenerateKey(), null);", "DNA0015")]
    public async Task Does_not_report_safe_or_unrelated_use(string statement, string rule)
    {
        var findings = await AnalyzeAsync(statement);
        Assert.DoesNotContain(findings, finding => finding.Id == rule);
    }

    [Theory]
    [InlineData("_ = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[32]);")]
    [InlineData("_ = NSec.Cryptography.Key.Import(NSec.Cryptography.AeadAlgorithm.Aes256Gcm, new byte[32], NSec.Cryptography.KeyBlobFormat.RawSymmetricKey);")]
    [InlineData("_ = Sodium.SecretBox.Create(new byte[1], new byte[24], new byte[32]);")]
    public async Task Reports_zeroed_keys_in_library_apis(string statement)
    {
        var findings = await AnalyzeAsync(statement, new HardcodedPasswordAnalyzer());
        Assert.Contains(findings, finding => finding.Id == "DNA0009");
    }

    [Fact]
    public async Task Does_not_report_generated_sodium_key_as_hardcoded()
    {
        var findings = await AnalyzeAsync(
            "_ = Sodium.SecretBox.Create(new byte[1], Sodium.SecretBox.GenerateNonce(), Sodium.SecretBox.GenerateKey());",
            new HardcodedPasswordAnalyzer());
        Assert.DoesNotContain(findings, finding => finding.Id == "DNA0009");
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string statement, DiagnosticAnalyzer? analyzer = null)
    {
        var source = "#pragma warning disable SYSLIB5006\nusing System.Security.Cryptography; class Demo { static void Run(byte[] nonce) { " + statement + " } }";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator).Select(path => MetadataReference.CreateFromFile(path)).ToList();
        references.Add(MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Identity.PasswordHasherOptions).Assembly.Location));
        references.Add(MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation).Assembly.Location));
        references.Add(MetadataReference.CreateFromFile(typeof(Org.BouncyCastle.Crypto.Parameters.KeyParameter).Assembly.Location));
        references.Add(MetadataReference.CreateFromFile(typeof(NSec.Cryptography.AeadAlgorithm).Assembly.Location));
        references.Add(MetadataReference.CreateFromFile(typeof(Sodium.SecretBox).Assembly.Location));
        var compilation = CSharpCompilation.Create("CryptoProbe",
            [CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview))],
            references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return await compilation.WithAnalyzers([analyzer ?? new CryptographyAnalyzer()]).GetAnalyzerDiagnosticsAsync();
    }
}
