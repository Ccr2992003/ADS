using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Channels;
using System.Threading.Tasks;

class AESECBParallel
{
    public static byte[] EncryptBlock(byte[] block, byte[] key)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            using (var encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(block, 0, block.Length);
            }
        }
    }

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

        Console.WriteLine("=== Channel-Based ECB Mode ===");

        var encryptionTimer = Stopwatch.StartNew();
        ProcessWithChannels(blocks, key, iterations, true).Wait();
        encryptionTimer.Stop();

        using (var ms = new MemoryStream())
        {
            foreach (var block in blocks)
            {
                ms.Write(block, 0, block.Length);
            }
            File.WriteAllBytes(encryptedFile, ms.ToArray());
        }
        Console.WriteLine($" Total Encryption time: {encryptionTimer.Elapsed}");

        var decryptionTimer = Stopwatch.StartNew();
        ProcessWithChannels(blocks, key, iterations, false).Wait();
        decryptionTimer.Stop();

        using (var ms = new MemoryStream())
        {
            foreach (var block in blocks)
            {
                ms.Write(block, 0, block.Length);
            }
            File.WriteAllBytes(decryptedFile, ms.ToArray());
        }
        Console.WriteLine($" Total Decryption time: {decryptionTimer.Elapsed}");
    }

    static async Task ProcessWithChannels(byte[][] blocks, byte[] key, int iterations, bool encrypt)
    {
        var channel = Channel.CreateBounded<(int index, byte[] block)>(new BoundedChannelOptions(512)
        {
            SingleWriter = true,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait
        });

        int processorCount = Environment.ProcessorCount;
        Task[] workers = new Task[processorCount];

        for (int w = 0; w < processorCount; w++)
        {
            workers[w] = Task.Run(async () =>
            {
                var reader = channel.Reader;
                while (await reader.WaitToReadAsync())
                {
                    while (reader.TryRead(out var item))
                    {
                        byte[] result = item.block;
                        for (int i = 0; i < iterations; i++)
                        {
                            result = encrypt ? EncryptBlock(result, key) : DecryptBlock(result, key);
                        }
                        blocks[item.index] = result;
                    }
                }
            });
        }

        var writer = channel.Writer;
        for (int i = 0; i < blocks.Length; i++)
        {
            await writer.WriteAsync((i, blocks[i]));
        }

        writer.Complete();
        await Task.WhenAll(workers);
    }
}
