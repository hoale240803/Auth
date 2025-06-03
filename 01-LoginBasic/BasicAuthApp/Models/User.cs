namespace BasicAuthApp.Models;

using System.Security.Cryptography;

public class User
{
    public string Username { get; set; }
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }
}

public static class UserStore
{
    private static readonly List<User> Users = new List<User>();

    public static User FindUser(string username) => Users.FirstOrDefault(u => u.Username == username);

    public static void AddUser(string username, string password)
    {
        var (hash, salt) = HashPassword(password);
        Users.Add(new User { Username = username, PasswordHash = hash, PasswordSalt = salt });
    }

    private static (byte[] hash, byte[] salt) HashPassword(string password)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, 16, 100000, HashAlgorithmName.SHA256);
        return (pbkdf2.GetBytes(32), pbkdf2.Salt);
    }

    public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, storedSalt, 100000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);
        return CryptographicOperations.FixedTimeEquals(hash, storedHash);
    }
}