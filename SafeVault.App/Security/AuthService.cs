using SafeVault.App.Models;

namespace SafeVault.App.Security;

/// <summary>
/// Provides authentication services with secure password hashing using BCrypt
/// </summary>
public class AuthService
{
    /// <summary>
    /// Hashes a password using BCrypt
    /// </summary>
    public static string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    /// <summary>
    /// Verifies a password against a hash
    /// </summary>
    public static bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Authenticates a user with username and password
    /// Returns the user if authentication is successful, null otherwise
    /// </summary>
    public static User? Login(string username, string password, List<User> users)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return null;

        // Find user by username
        var user = users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        
        if (user == null)
            return null;

        // Verify password
        if (!VerifyPassword(password, user.PasswordHash))
            return null;

        return user;
    }

    /// <summary>
    /// Validates password strength
    /// Password must be at least 8 characters with uppercase, lowercase, digit, and special character
    /// </summary>
    public static bool IsStrongPassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 8)
            return false;

        bool hasUpper = password.Any(char.IsUpper);
        bool hasLower = password.Any(char.IsLower);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}
