
using OtpNet;
using QRCoder;

namespace CustomJWTWith2FA.Services
{
    public class TwoFactorService
    {
        public (string secret, string qrCodeUrl) Generate2FASecret(string username, string issuer)
        {
            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var secret = Base32Encoding.ToString(secretKey);
            var qrCodeUrl = $"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}";
            return (secret, qrCodeUrl);
        }

        public string GenerateQrCodePng(string qrCodeUrl)
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(qrCodeUrl, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);
            return Convert.ToBase64String(qrCodeBytes);
        }

        public bool Verify2FACode(string secret, string code)
        {
            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(secretBytes);
            var accurateCode = totp.ComputeTotp();


            return totp.VerifyTotp(code, out _, new VerificationWindow(2));
        }
    }
}