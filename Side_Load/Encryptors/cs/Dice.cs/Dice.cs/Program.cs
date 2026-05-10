using System.Security.Cryptography;

if (args.Length != 2)
{
    Console.WriteLine("Usage: Dice.exe <config_file> <target_file>");
    Environment.Exit(1);
}

string configFilePath = args[0];
string targetFilePath = args[1];

var config = ReadConfiguration(configFilePath);
int numberOfFiles = int.Parse(config["NumberOfFiles"]);
string encryptionKey = config["EncryptionKey"];

// Output paths are relative to the config file's directory (Side_Load/)
string configDir = Path.GetDirectoryName(Path.GetFullPath(configFilePath))!;
string downloadsDir = Path.Combine(configDir, "Decryptor", "Downloads");
string partsDir = Path.Combine(downloadsDir, "parts");
Directory.CreateDirectory(partsDir);

byte[] plaintext = File.ReadAllBytes(targetFilePath);

// PBKDF2-SHA256 key derivation — matches Python slice.py parameters
byte[] salt = RandomNumberGenerator.GetBytes(16);
using var rfc = new Rfc2898DeriveBytes(encryptionKey, salt, 100_000, HashAlgorithmName.SHA256);
byte[] key = rfc.GetBytes(16);

// AES-128-CBC encryption with PKCS7 padding
byte[] iv = RandomNumberGenerator.GetBytes(16);
using var aes = Aes.Create();
aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.PKCS7;
aes.Key = key;
aes.IV = iv;
using var encryptor = aes.CreateEncryptor();
byte[] ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

File.WriteAllBytes(Path.Combine(downloadsDir, "iv.bin"), iv);
File.WriteAllBytes(Path.Combine(downloadsDir, "salt.bin"), salt);
Console.WriteLine("IV saved to iv.bin.");
Console.WriteLine("salt saved to salt.bin.");

// Split ciphertext into N parts — same distribution as slice.py
string targetFileName = Path.GetFileName(targetFilePath);
int chunkSize = ciphertext.Length / numberOfFiles;
int remainder = ciphertext.Length % numberOfFiles;

for (int i = 0; i < numberOfFiles; i++)
{
    int offset = (i * chunkSize) + Math.Min(i, remainder);
    int partSize = chunkSize + (i < remainder ? 1 : 0);
    byte[] part = ciphertext[offset..(offset + partSize)];

    string partPath = Path.Combine(partsDir, $"{targetFileName}_part_{i}");
    File.WriteAllBytes(partPath, part);
    Console.WriteLine($"Saving {partPath}");
}

Console.WriteLine($"Encrypted file split into {numberOfFiles} parts.");

static Dictionary<string, string> ReadConfiguration(string filePath)
{
    var cfg = new Dictionary<string, string>();

    if (!File.Exists(filePath))
    {
        Console.WriteLine("Configuration file not found.");
        Environment.Exit(1);
    }

    foreach (var line in File.ReadAllLines(filePath))
    {
        int eq = line.IndexOf('=');
        if (eq > 0)
        {
            cfg[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }
    }

    return cfg;
}
