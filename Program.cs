using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

class AESECBParallel
{
    // Encrypt a single block using ECB mode
    public static byte[] EncryptBlock(byte[] block, byte[] key)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;  // Independent blocks
            aes.Padding = PaddingMode.PKCS7;
            using (var encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(block, 0, block.Length);
            }
        }
    }

    // Decrypt a single block using ECB mode
    public static byte[] DecryptBlock(byte[] block, byte[] key)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            using (var decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(block, 0, block.Length);
            }
        }
    }

    static void Main()
    {
        string inputFile = "Al_Saselea_Input.txt";
        string encryptedFile = "encrypted.txt";
        string decryptedFile = "decrypted.txt";
        int iterations = 9000;
        byte[] data = File.ReadAllBytes(inputFile);

        byte[] key;
        using (var aes = Aes.Create())
        {
            aes.GenerateKey();
            key = aes.Key;
        }

        int blockSize = 16384;
        int blockCount = (data.Length + blockSize - 1) / blockSize;
        byte[][] blocks = new byte[blockCount][];
        for (int i = 0; i < blockCount; i++)
        {
            int currentBlockSize = Math.Min(blockSize, data.Length - i * blockSize);
            blocks[i] = new byte[currentBlockSize];
            Array.Copy(data, i * blockSize, blocks[i], 0, currentBlockSize);
        }

        Console.WriteLine("=== Parallel ECB Mode ===");
        Stopwatch encryptionTimer = Stopwatch.StartNew();
        // Parallel encryption: process each block independently
        Parallel.For(0, blockCount, i =>
        {
            byte[] block = blocks[i];
            // Perform the iterative encryption on each block
            for (int j = 0; j < iterations; j++)
            {
                block = EncryptBlock(block, key);
            }
            blocks[i] = block;
        });
        encryptionTimer.Stop();

        // Combine encrypted blocks back into a single byte array
        using (var ms = new MemoryStream())
        {
            foreach (var block in blocks)
            {
                ms.Write(block, 0, block.Length);
            }
            File.WriteAllBytes(encryptedFile, ms.ToArray());
        }
        Console.WriteLine($"[Parallel] Total Encryption time: {encryptionTimer.Elapsed}");

        // Now for decryption (using the reverse process)
        Stopwatch decryptionTimer = Stopwatch.StartNew();
        Parallel.For(0, blockCount, i =>
        {
            byte[] block = blocks[i];
            // Reverse the iterations for decryption
            for (int j = 0; j < iterations; j++)
            {
                block = DecryptBlock(block, key);
            }
            blocks[i] = block;
        });
        decryptionTimer.Stop();

        // Combine decrypted blocks and write to file
        using (var ms = new MemoryStream())
        {
            foreach (var block in blocks)
            {
                ms.Write(block, 0, block.Length);
            }
            File.WriteAllBytes(decryptedFile, ms.ToArray());
        }
        Console.WriteLine($"[Parallel] Total Decryption time: {decryptionTimer.Elapsed}");
    }
}
