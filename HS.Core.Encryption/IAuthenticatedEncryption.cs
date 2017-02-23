namespace HS.Core.Encryption
{
    public interface IAuthenticatedEncryption
    {
        byte[] Decrypt(byte[] bytes, byte[] key, byte[] macKey);

        byte[] Encrypt(byte[] bytes, byte[] key, byte[] macKey);
    }
}