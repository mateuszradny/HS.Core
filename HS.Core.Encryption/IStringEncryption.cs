namespace HS.Core.Encryption
{
    public interface IStringEncryption
    {
        string Decrypt(string text, string password);

        string Encrypt(string text, string password);
    }
}