using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace HS.Core.Encryption
{
    public sealed class AuthenticatedEncryption<TSymmetricAlgorithm, TKeyedHashAlgorithm> : IAuthenticatedEncryption
            where TSymmetricAlgorithm : SymmetricAlgorithm, new()
            where TKeyedHashAlgorithm : KeyedHashAlgorithm, new()
    {
        public byte[] Decrypt(byte[] bytes, byte[] key, byte[] macKey)
        {
            if (bytes == null || bytes.Length == 0)
                throw new ArgumentException("The bytes to decrypt can't be empty", nameof(bytes));

            if (key == null || key.Length == 0)
                throw new ArgumentException("The key used in the encryption algorithm can't be empty", nameof(key));

            if (macKey == null || macKey.Length == 0)
                throw new ArgumentException("The key used in the hash algorithm can't be empty", nameof(macKey));

            using (var symmetricAlgorithm = new TSymmetricAlgorithm() { Key = key })
            using (var keyedHashAlgorithm = new TKeyedHashAlgorithm() { Key = macKey })
            {
                if (symmetricAlgorithm.BlockSize + keyedHashAlgorithm.HashSize >= bytes.Length * 8)
                    throw new ArgumentException("Size of bytes to decrypt is invalid", "bytes");

                byte[] mac = new byte[keyedHashAlgorithm.HashSize / 8];
                Array.Copy(bytes, bytes.Length - mac.Length, mac, 0, mac.Length);

                byte[] computedMac = keyedHashAlgorithm.ComputeHash(bytes, 0, bytes.Length - mac.Length);

                if (!mac.SequenceEqual(computedMac))
                    throw new CryptographicException("The MAC is invalid");

                byte[] iv = new byte[symmetricAlgorithm.BlockSize / 8];
                Array.Copy(bytes, iv, iv.Length);

                byte[] encryptedBytes = new byte[bytes.Length - iv.Length - mac.Length];
                Array.Copy(bytes, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

                symmetricAlgorithm.IV = iv;

                using (var decryptor = symmetricAlgorithm.CreateDecryptor())
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        binaryWriter.Write(encryptedBytes);
                    }

                    return memoryStream.ToArray();
                }
            }
        }

        public byte[] Encrypt(byte[] bytes, byte[] key, byte[] macKey)
        {
            if (bytes == null || bytes.Length == 0)
                throw new ArgumentException("The bytes to encrypt can't be empty", nameof(bytes));

            if (key == null || key.Length == 0)
                throw new ArgumentException("The key used in the encryption algorithm can't be empty", nameof(bytes));

            if (macKey == null || macKey.Length == 0)
                throw new ArgumentException("The key used in the hash algorithm can't be empty", nameof(bytes));

            byte[] encryptedBytes;
            byte[] iv;

            using (var symmetricAlgorithm = new TSymmetricAlgorithm() { Key = key })
            {
                iv = symmetricAlgorithm.IV;

                using (var encryptor = symmetricAlgorithm.CreateEncryptor())
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        binaryWriter.Write(bytes);
                    }

                    encryptedBytes = memoryStream.ToArray();
                }
            }

            using (var keyedHashAlgorithm = new TKeyedHashAlgorithm() { Key = macKey })
            using (var memoryStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(memoryStream))
                {
                    binaryWriter.Write(iv);
                    binaryWriter.Write(encryptedBytes);
                    binaryWriter.Flush();

                    byte[] mac = keyedHashAlgorithm.ComputeHash(memoryStream.ToArray());
                    binaryWriter.Write(mac);
                }

                return memoryStream.ToArray();
            }
        }
    }
}