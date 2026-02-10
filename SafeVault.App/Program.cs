using SafeVault.App.Models;
using SafeVault.App.Security;

namespace SafeVault.App;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== SafeVault - Secure Authentication & Authorization Demo ===\n");

        // Demo users list (in real app, this would be a database)
        var users = new List<User>();

        // Activity 1: Input Sanitization Demo
        Console.WriteLine("--- Activity 1: Input Sanitization ---");
        DemoInputSanitization();

        // Activity 2: Authentication Demo
        Console.WriteLine("\n--- Activity 2: Authentication ---");
        var admin = DemoAuthentication(users);

        // Activity 2: Authorization Demo
        Console.WriteLine("\n--- Activity 2: Authorization ---");
        DemoAuthorization(admin, users);

        Console.WriteLine("\n=== Demo Complete ===");
    }

    static void DemoInputSanitization()
    {
        // XSS Protection
        string maliciousInput = "<script>alert('XSS')</script>";
        string sanitized = InputSanitizer.SanitizeForXss(maliciousInput);
        Console.WriteLine($"Original: {maliciousInput}");
        Console.WriteLine($"Sanitized: {sanitized}");

        // SQL Injection Detection
        string sqlInjection = "admin' OR '1'='1";
        bool isSqlInjection = InputSanitizer.ContainsSqlInjectionPattern(sqlInjection);
        Console.WriteLine($"\nInput: {sqlInjection}");
        Console.WriteLine($"Contains SQL Injection Pattern: {isSqlInjection}");

        // Email Validation
        string validEmail = "user@example.com";
        string invalidEmail = "not-an-email";
        Console.WriteLine($"\n'{validEmail}' is valid email: {InputSanitizer.IsValidEmail(validEmail)}");
        Console.WriteLine($"'{invalidEmail}' is valid email: {InputSanitizer.IsValidEmail(invalidEmail)}");

        // Username Validation
        string validUsername = "john_doe123";
        string invalidUsername = "john@doe";
        Console.WriteLine($"\n'{validUsername}' is valid username: {InputSanitizer.IsValidUsername(validUsername)}");
        Console.WriteLine($"'{invalidUsername}' is valid username: {InputSanitizer.IsValidUsername(invalidUsername)}");
    }

    static User DemoAuthentication(List<User> users)
    {
        // Create an admin user
        string password = "SecurePass123!";
        string passwordHash = AuthService.HashPassword(password);
        
        var admin = new User
        {
            Id = 1,
            Username = "admin",
            Email = "admin@safevault.com",
            PasswordHash = passwordHash,
            Role = "admin"
        };
        users.Add(admin);

        Console.WriteLine("Created admin user with hashed password");
        Console.WriteLine($"Password: {password}");
        Console.WriteLine($"Hash: {passwordHash.Substring(0, 20)}...");

        // Test valid login
        var loginResult = AuthService.Login("admin", password, users);
        Console.WriteLine($"\nLogin with correct password: {(loginResult != null ? "SUCCESS" : "FAILED")}");

        // Test invalid login
        loginResult = AuthService.Login("admin", "wrongpassword", users);
        Console.WriteLine($"Login with wrong password: {(loginResult != null ? "SUCCESS" : "FAILED")}");

        // Test password strength
        Console.WriteLine($"\nPassword strength check:");
        Console.WriteLine($"'weak' is strong: {AuthService.IsStrongPassword("weak")}");
        Console.WriteLine($"'SecurePass123!' is strong: {AuthService.IsStrongPassword("SecurePass123!")}");

        return admin;
    }

    static void DemoAuthorization(User admin, List<User> users)
    {
        // Create a regular user
        var user = new User
        {
            Id = 2,
            Username = "john_doe",
            Email = "john@example.com",
            PasswordHash = AuthService.HashPassword("UserPass123!"),
            Role = "user"
        };
        users.Add(user);

        // Check admin privileges
        Console.WriteLine($"Admin user is admin: {RoleAuthorization.IsAdmin(admin)}");
        Console.WriteLine($"Regular user is admin: {RoleAuthorization.IsAdmin(user)}");

        // Check resource access
        int resourceOwnerId = 2; // Resource owned by john_doe
        Console.WriteLine($"\nResource access (Owner ID: {resourceOwnerId}):");
        Console.WriteLine($"Admin can access: {RoleAuthorization.CanAccessResource(admin, resourceOwnerId)}");
        Console.WriteLine($"Owner can access: {RoleAuthorization.CanAccessResource(user, resourceOwnerId)}");

        // Test requiring admin role
        try
        {
            Console.WriteLine("\nTrying admin-only operation with admin user...");
            RoleAuthorization.RequireAdmin(admin);
            Console.WriteLine("SUCCESS: Admin operation allowed");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"FAILED: {ex.Message}");
        }

        try
        {
            Console.WriteLine("\nTrying admin-only operation with regular user...");
            RoleAuthorization.RequireAdmin(user);
            Console.WriteLine("SUCCESS: Admin operation allowed");
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"FAILED: {ex.Message}");
        }
    }
}
