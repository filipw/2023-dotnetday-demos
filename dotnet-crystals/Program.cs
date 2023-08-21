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

    var message = AnsiConsole.Ask<string>("Please provide a [green]message[/]?");
    var data = Hex.Encode(Encoding.ASCII.GetBytes(message));
    var random = new SecureRandom();
    var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
    var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
    dilithiumKeyPairGenerator.Init(keyGenParameters);

    var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

    // get and view the keys
    var publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
    var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
    var pubEncoded = publicKey.GetEncoded();
    var privateEncoded = privateKey.GetEncoded();
    
    var panel = new Panel($":unlocked: Public: {PrettyPrint(pubEncoded)}{Environment.NewLine}:locked: Private: {PrettyPrint(privateEncoded)}")
        {
            Header = new PanelHeader("Keys")
        };
    AnsiConsole.Write(panel);

    // sign
    var alice = new DilithiumSigner();
    alice.Init(true, privateKey);
    var signature = alice.GenerateSignature(data);
    var panel2 = new Panel($":pen: {PrettyPrint(signature)}")
    {
        Header = new PanelHeader("Signature")
    };
    AnsiConsole.Write(panel2);

    // verify signature
    var bob = new DilithiumSigner();
    bob.Init(false, publicKey);
    var verified = bob.VerifySignature(data, signature);
    
    var panel3 = new Panel($"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!")
    {
        Header = new PanelHeader("Verification")
    };
    AnsiConsole.Write(panel3);
}

static void RunKyber() 
{
    var rule = new Rule("[green]Kyber[/]");
    AnsiConsole.Write(rule);
    
    var random = new SecureRandom();
    var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber768);
    var kyberKeyPairGenerator = new KyberKeyPairGenerator();
    kyberKeyPairGenerator.Init(keyGenParameters);

    // generate key pair for Alice
    var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();

    // get and view the keys
    var alicePublic = (KyberPublicKeyParameters)aliceKeyPair.Public;
    var alicePrivate = (KyberPrivateKeyParameters)aliceKeyPair.Private;
    var pubEncoded = alicePublic.GetEncoded();
    var privateEncoded = alicePrivate.GetEncoded();
    var panel = new Panel($":unlocked: Public: {PrettyPrint(pubEncoded)}{Environment.NewLine}:locked: Private: {PrettyPrint(privateEncoded)}")
    {
        Header = new PanelHeader("Alice's keys")
    };
    AnsiConsole.Write(panel);

    // Bob encapsulates a new shared secret using Alice's public key
    var bobKyberKemGenerator = new KyberKemGenerator(random);
    var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(alicePublic);
    var bobSecret = encapsulatedSecret.GetSecret();

    // cipher text produced by Bob and sent to Alice
    var cipherText = encapsulatedSecret.GetEncapsulation();

    // Alice decapsulates a new shared secret using Alice's private key
    var aliceKemExtractor = new KyberKemExtractor(alicePrivate);
    var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);
    
    var panel2 = new Panel($":man: Bob's secret: {PrettyPrint(bobSecret)}{Environment.NewLine}:locked_with_key: Cipher text (Bob -> Alice): {PrettyPrint(cipherText)}{Environment.NewLine}:woman: Alice's secret: {PrettyPrint(aliceSecret)}")
    {
        Header = new PanelHeader("KEM")
    };
    AnsiConsole.Write(panel2);

    // Compare secrets
    var equal = bobSecret.SequenceEqual(aliceSecret);
    var panel3 = new Panel($"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal!")
    {
        Header = new PanelHeader("Verification")
    };
    AnsiConsole.Write(panel3);
}

static string PrettyPrint(byte[] bytes) {
    var base64 = Convert.ToBase64String(bytes);
    return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
}