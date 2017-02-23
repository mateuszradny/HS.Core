using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace HS.Core.Encryption.Tests
{
    [TestFixture]
    public class AuthenticatedEncryptionTests
    {
        private static Type[] TSymmetricAlgorithms =
        {
            typeof(AesManaged),
            typeof(DESCryptoServiceProvider),
            typeof(RC2CryptoServiceProvider),
            typeof(RijndaelManaged),
            typeof(TripleDESCryptoServiceProvider)
        };

        private static Type[] TKeyedHashAlgorithms =
        {
            typeof(HMACMD5),
            typeof(HMACRIPEMD160),
            typeof(HMACSHA1),
            typeof(HMACSHA256),
            typeof(HMACSHA384),
            typeof(HMACSHA512),
            typeof(MACTripleDES)
        };

        [Test]
        public void UseCase()
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = { 251, 9, 67, 117, 237, 158, 138, 150, 255, 97, 103, 128, 183, 65, 76, 161, 7, 79, 244, 225, 146, 180, 51, 123, 118, 167, 45, 10, 184, 181, 202, 190 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();
            var encrypted = encryption.Encrypt(bytes, key, macKey);
            var decrypted = encryption.Decrypt(encrypted, key, macKey);

            Assert.That(bytes, Is.EquivalentTo(decrypted));
        }

        [Test]
        public void UseDifferentAlgorithms(
            [ValueSource("TSymmetricAlgorithms")] Type TSymmetricAlgorithm,
            [ValueSource("TKeyedHashAlgorithms")] Type TKeyedHashAlgorithm)
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = ((SymmetricAlgorithm)Activator.CreateInstance(TSymmetricAlgorithm)).Key;
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = (IAuthenticatedEncryption)Activator.CreateInstance(typeof(AuthenticatedEncryption<,>).MakeGenericType(TSymmetricAlgorithm, TKeyedHashAlgorithm));
            var encrypted = encryption.Encrypt(bytes, key, macKey);
            var decrypted = encryption.Decrypt(encrypted, key, macKey);

            Assert.That(bytes, Is.EquivalentTo(decrypted));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        [TestCase(new byte[] { 69 })] // Size of bytes to decrypt must be at least greater than size of IV + HashSize
        public void Decrypt_InvalidBytes_ThrowException(byte[] bytes)
        {
            byte[] key = { 251, 9, 67, 117, 237, 158, 138, 150, 255, 97, 103, 128, 183, 65, 76, 161, 7, 79, 244, 225, 146, 180, 51, 123, 118, 167, 45, 10, 184, 181, 202, 190 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Decrypt(bytes, key, macKey));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        public void Decrypt_InvalidKey_ThrowException(byte[] key)
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Decrypt(bytes, key, macKey));
        }

        [Test]
        public void Decrypt_InvalidKeySize_ThrowException()
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = { 69 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<CryptographicException>(() => encryption.Decrypt(bytes, key, macKey));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        public void Decrypt_InvalidMacKey_ThrowException(byte[] macKey)
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = { 251, 9, 67, 117, 237, 158, 138, 150, 255, 97, 103, 128, 183, 65, 76, 161, 7, 79, 244, 225, 146, 180, 51, 123, 118, 167, 45, 10, 184, 181, 202, 190 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Decrypt(bytes, key, macKey));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        public void Encrypt_InvalidBytes_ThrowException(byte[] bytes)
        {
            byte[] key = { 251, 9, 67, 117, 237, 158, 138, 150, 255, 97, 103, 128, 183, 65, 76, 161, 7, 79, 244, 225, 146, 180, 51, 123, 118, 167, 45, 10, 184, 181, 202, 190 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Encrypt(bytes, key, macKey));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        public void Encrypt_InvalidKey_ThrowException(byte[] key)
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Encrypt(bytes, key, macKey));
        }

        [Test]
        public void Encrypt_InvalidKeySize_ThrowException()
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = { 69 };
            byte[] macKey = { 214, 11, 221, 108, 210, 71, 14, 15, 151, 57, 241, 174, 177, 142, 115, 137 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<CryptographicException>(() => encryption.Encrypt(bytes, key, macKey));
        }

        [TestCase(null)]
        [TestCase(new byte[] { })]
        public void Encrypt_InvalidMacKey_ThrowException(byte[] macKey)
        {
            byte[] bytes = { 214, 11, 221, 108, 210, 71, 14, 15 };
            byte[] key = { 251, 9, 67, 117, 237, 158, 138, 150, 255, 97, 103, 128, 183, 65, 76, 161, 7, 79, 244, 225, 146, 180, 51, 123, 118, 167, 45, 10, 184, 181, 202, 190 };

            var encryption = new AuthenticatedEncryption<AesManaged, HMACSHA256>();

            Assert.Throws<ArgumentException>(() => encryption.Encrypt(bytes, key, macKey));
        }
    }
}