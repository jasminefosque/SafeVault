using System.Text.RegularExpressions;

namespace SafeVault.App.Security;

/// <summary>
/// Provides input sanitization to prevent XSS and SQL injection attacks
/// </summary>
public class InputSanitizer
{
    /// <summary>
    /// Sanitizes input to prevent XSS attacks by encoding HTML special characters
    /// </summary>
    public static string SanitizeForXss(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        return input
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#x27;")
            .Replace("/", "&#x2F;");
    }

    /// <summary>
    /// Validates input for SQL injection patterns
    /// Returns true if input contains suspicious SQL patterns
    /// </summary>
    public static bool ContainsSqlInjectionPattern(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        // Common SQL injection patterns
        string[] sqlPatterns = new[]
        {
            @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)",
            @"(--|\#|\/\*|\*\/)",
            @"('|(;|=))",
            @"(\bOR\b\s+\d+\s*=\s*\d+)",
            @"(\bAND\b\s+\d+\s*=\s*\d+)",
            @"(xp_|sp_)"
        };

        foreach (var pattern in sqlPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Validates email format
    /// </summary>
    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        try
        {
            var emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return Regex.IsMatch(email, emailPattern, RegexOptions.IgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates username format (alphanumeric and underscore only)
    /// </summary>
    public static bool IsValidUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        var usernamePattern = @"^[a-zA-Z0-9_]{3,20}$";
        return Regex.IsMatch(username, usernamePattern);
    }

    /// <summary>
    /// Sanitizes input for safe usage in SQL context
    /// Note: This should be used in conjunction with parameterized queries
    /// </summary>
    public static string SanitizeForSql(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // Remove or escape dangerous characters
        return input
            .Replace("'", "''")
            .Replace(";", "")
            .Replace("--", "")
            .Replace("/*", "")
            .Replace("*/", "")
            .Replace("xp_", "")
            .Replace("sp_", "");
    }
}
