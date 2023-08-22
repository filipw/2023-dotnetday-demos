using System.Text;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Spectre.Console;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(new[]
        {
            "Kyber", "Dilithium"
        }));

switch (demo)
{
    case "Kyber":
        RunKyber();
        break;
    case "Dilithium":
        RunDilithium();
        break;
    default:
        Console.WriteLine("Nothing selected!");
        break;
}

static void RunDilithium()
{
    var rule = new Rule("[green]Dilithium[/]");
    AnsiConsole.Write(rule);
    
    // 1. prepare data
    var message = AnsiConsole.Ask<string>("Please provide a [green]message[/]?");
    var data = Hex.Encode(Encoding.ASCII.GetBytes(message));
    
    // 2. set up Dilithium
    var random = new SecureRandom();
    var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
    var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
    dilithiumKeyPairGenerator.Init(keyGenParameters);

    // 3. generate and view private and public keys
    var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
    var publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
    var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
    var pubEncoded = publicKey.GetEncoded();
    var privateEncoded = privateKey.GetEncoded();
    PrintPanel("Keys", new[] { $":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}" });

    // 4. sign the data
    var alice = new DilithiumSigner();
    alice.Init(true, privateKey);
    var signature = alice.GenerateSignature(data);
    PrintPanel("Signature", new[] { $":pen: {signature.PrettyPrint()}" });
    
    // 5. verify signature
    var bob = new DilithiumSigner();
    bob.Init(false, publicKey);
    var verified = bob.VerifySignature(data, signature);
    PrintPanel("Verification", new[] { $"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!" });
}

static void RunKyber() 
{
    var rule = new Rule("[green]Kyber[/]");
    AnsiConsole.Write(rule);
    
    // 1. set up Kyber
    var random = new SecureRandom();
    var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber768);
    var kyberKeyPairGenerator = new KyberKeyPairGenerator();
    kyberKeyPairGenerator.Init(keyGenParameters);
    
    // 2. generate and view private and public keys for Alice
    var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();
    var alicePublic = (KyberPublicKeyParameters)aliceKeyPair.Public;
    var alicePrivate = (KyberPrivateKeyParameters)aliceKeyPair.Private;
    var pubEncoded = alicePublic.GetEncoded();
    var privateEncoded = alicePrivate.GetEncoded();
    PrintPanel("Alice's keys", new[] { $":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}" });

    // 3. Bob encapsulates a new shared secret using Alice's public key
    var bobKyberKemGenerator = new KyberKemGenerator(random);
    var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(alicePublic);
    var bobSecret = encapsulatedSecret.GetSecret();
    var cipherText = encapsulatedSecret.GetEncapsulation();

    // 4. Alice decapsulates a new shared secret using Alice's private key
    var aliceKemExtractor = new KyberKemExtractor(alicePrivate);
    var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);
    PrintPanel("Key encapsulation", new[] { $":man: Bob's secret: {bobSecret.PrettyPrint()}", $":locked_with_key: Cipher text (Bob -> Alice): {cipherText.PrettyPrint()}", $":woman: Alice's secret: {aliceSecret.PrettyPrint()}" });

    // Compare secrets
    var equal = bobSecret.SequenceEqual(aliceSecret);
    PrintPanel("Verification", new[] { $"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal!" });
}

static void PrintPanel(string header, string[] data)
{
    var content = string.Join(Environment.NewLine, data);
    var panel = new Panel(content)
    {
        Header = new PanelHeader(header)
    };
    AnsiConsole.Write(panel);
}

public static class FormatExtensions
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }
}