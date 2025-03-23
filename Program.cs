using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class AES
{
    public static byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }

    public static byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream(data))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var reader = new MemoryStream())
            {
                cs.CopyTo(reader);
                return reader.ToArray();
            }
        }
    }

    static void Main()
    {
        string inputFile = "final.txt";
        string encryptedFile = "encrypted.txt";
        string decryptedFile = "decrypted.txt";
        int iterations = 9000; 

        byte[] data = File.ReadAllBytes(inputFile);

        using (var aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();

            Console.WriteLine("=== Sequential Mode ===");
            Stopwatch encryptionTimer = Stopwatch.StartNew();

            byte[] encryptedData = data;
            for (int i = 0; i < iterations; i++)
            {
                encryptedData = EncryptData(encryptedData, aes.Key, aes.IV);
            }
            encryptionTimer.Stop();
            File.WriteAllBytes(encryptedFile, encryptedData);
            Console.WriteLine($"[Sequential] Total Encryption time: {encryptionTimer.Elapsed}");

            Stopwatch decryptionTimer = Stopwatch.StartNew();
            byte[] decryptedData = encryptedData;
            for (int i = 0; i < iterations; i++)
            {
                decryptedData = DecryptData(decryptedData, aes.Key, aes.IV);
            }
            decryptionTimer.Stop();
            File.WriteAllBytes(decryptedFile, decryptedData);
            Console.WriteLine($"[Sequential] Total Decryption time: {decryptionTimer.Elapsed}");
        }
    }
}
