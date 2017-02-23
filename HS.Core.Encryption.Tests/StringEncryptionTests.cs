using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace HS.Core.Encryption.Tests
{
    [TestFixture]
    public class StringEncryptionTests
    {
        [Test]
        public void UseCase()
        {
            string text = "HS.Core.Encryption";
            string password = "zaq1@WSX";

            var encryption = new StringEncryption();
            var encrypted = encryption.Encrypt(text, password);
            var decrypted = encryption.Decrypt(encrypted, password);

            Assert.AreEqual(text, decrypted);
        }

        [Test]
        public void UseDifferentPasswordsFails()
        {
            string text = "HS.Core.Encryption";
            string password1 = "zaq1@WSX";
            string password2 = "1234qwer";

            var encryption = new StringEncryption();
            var encrypted = encryption.Encrypt(text, password1);

            Assert.Throws<CryptographicException>(() => encryption.Decrypt(encrypted, password2));
        }

        [Test]
        public void EncryptWork()
        {
            string text = "HS.Core.Encryption";
            string password = "zaq1@WSX";

            var encryption = new StringEncryption();
            var encrypted = encryption.Encrypt(text, password);

            Assert.AreNotEqual(text, encrypted);
        }

        [Test]
        public void DecryptWork()
        {
            string text = "HS.Core.Encryption";
            string password = "zaq1@WSX";

            var encryption = new StringEncryption();
            var encrypted = encryption.Encrypt(text, password);
            var decrypted = encryption.Decrypt(encrypted, password);

            Assert.AreNotEqual(encrypted, decrypted);
        }

        [TestCase(null)]
        [TestCase("")]
        public void Encrypt_InvalidText_ThrowException(string text)
        {
            string password = "zaq1@WSX";

            var encryption = new StringEncryption();
            Assert.Throws<ArgumentException>(() => encryption.Encrypt(text, password));
        }

        [TestCase(null)]
        [TestCase("")]
        public void Encrypt_InvalidPassword_ThrowException(string password)
        {
            string text = "HS.Core.Encryption";

            var encryption = new StringEncryption();
            Assert.Throws<ArgumentException>(() => encryption.Encrypt(text, password));
        }

        [TestCase(null)]
        [TestCase("")]
        public void Decrypt_InvalidText_ThrowException(string text)
        {
            string password = "zaq1@WSX";

            var encryption = new StringEncryption();
            Assert.Throws<ArgumentException>(() => encryption.Decrypt(text, password));
        }

        [TestCase(null)]
        [TestCase("")]
        public void Decrypt_InvalidPassword_ThrowException(string password)
        {
            string text = "HS.Core.Encryption";

            var encryption = new StringEncryption();
            Assert.Throws<ArgumentException>(() => encryption.Decrypt(text, password));
        }
    }
}