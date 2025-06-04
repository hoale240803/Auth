using System.Security.Cryptography;
using System.Text;
using CustomJWTWithSessionManagement.Models;

namespace CustomJWTWithSessionManagement.Services
{
    public class SessionService
    {
        public string GenerateSessionToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public string GenerateDeviceFingerprint(string ipAddress, string userAgent)
        {
            // Simple fingerprint: hash of IP + User-Agent
            var input = $"{ipAddress}:{userAgent}";
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash)[..16]; // Truncate for brevity
        }

        public Session CreateSession(string username, string ipAddress, string userAgent)
        {
            return new Session
            {
                SessionToken = GenerateSessionToken(),
                LoginTimestamp = DateTime.UtcNow,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                IsActive = true,
                LastActivity = DateTime.UtcNow,
                DeviceFingerprint = GenerateDeviceFingerprint(ipAddress, userAgent)
            };
        }
    }
}