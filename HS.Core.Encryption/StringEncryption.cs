using System;
using System.Security.Cryptography;

namespace HS.Core.Encryption
{
    public sealed class StringEncryption : IStringEncryption
    {
        private readonly IAuthenticatedEncryption encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();
        private readonly byte[] salt = new byte[] { 10, 228, 160, 89, 20, 231, 98, 48 };

        public string Decrypt(string text, string password)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentException("The text to decrypt can't be empty", nameof(text));

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("The password used to decrypt can't be empty", nameof(password));

            byte[] encrypted = Convert.FromBase64String(text);

            byte[] key;
            byte[] macKey;

            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt))
            {
                key = deriveBytes.GetBytes(32);
                macKey = deriveBytes.GetBytes(64);
            }

            byte[] bytes = encryption.Decrypt(encrypted, key, macKey);
            return GetString(bytes);
        }

        public string Encrypt(string text, string password)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentException("The text to encrypt can't be empty", nameof(text));

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("The password used to encrypt can't be empty", nameof(password));

            byte[] bytes = GetBytes(text);

            byte[] key;
            byte[] macKey;

            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt))
            {
                key = deriveBytes.GetBytes(32);
                macKey = deriveBytes.GetBytes(64);
            }

            byte[] encrypted = encryption.Encrypt(bytes, key, macKey);
            return Convert.ToBase64String(encrypted);
        }

        private static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        private static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }
}