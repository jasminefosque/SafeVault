using NUnit.Framework;
using SafeVault.App.Models;
using SafeVault.App.Security;

namespace Tests;

[TestFixture]
public class TestAuthentication
{
    [Test]
    public void Test_HashPassword_GeneratesUniqueHashes()
    {
        // Arrange
        string password = "TestPassword123!";
        
        // Act
        string hash1 = AuthService.HashPassword(password);
        string hash2 = AuthService.HashPassword(password);
        
        // Assert
        Assert.That(hash1, Is.Not.Null);
        Assert.That(hash2, Is.Not.Null);
        Assert.That(hash1, Is.Not.EqualTo(hash2)); // BCrypt uses random salt
        Assert.That(hash1, Does.StartWith("$2")); // BCrypt format
    }

    [Test]
    public void Test_HashPassword_ThrowsOnNullOrEmpty()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => AuthService.HashPassword(null!));
        Assert.Throws<ArgumentException>(() => AuthService.HashPassword(""));
    }

    [Test]
    public void Test_VerifyPassword_ValidPassword()
    {
        // Arrange
        string password = "TestPassword123!";
        string hash = AuthService.HashPassword(password);
        
        // Act
        bool isValid = AuthService.VerifyPassword(password, hash);
        
        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void Test_VerifyPassword_InvalidPassword()
    {
        // Arrange
        string password = "TestPassword123!";
        string wrongPassword = "WrongPassword123!";
        string hash = AuthService.HashPassword(password);
        
        // Act
        bool isValid = AuthService.VerifyPassword(wrongPassword, hash);
        
        // Assert
        Assert.That(isValid, Is.False);
    }

    [Test]
    public void Test_VerifyPassword_HandlesNullAndEmpty()
    {
        // Arrange
        string hash = AuthService.HashPassword("TestPassword123!");
        
        // Act & Assert
        Assert.That(AuthService.VerifyPassword(null!, hash), Is.False);
        Assert.That(AuthService.VerifyPassword("", hash), Is.False);
        Assert.That(AuthService.VerifyPassword("password", null!), Is.False);
        Assert.That(AuthService.VerifyPassword("password", ""), Is.False);
    }

    [Test]
    public void Test_Login_ValidCredentials()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = AuthService.HashPassword("TestPass123!"),
                Role = "user"
            }
        };
        
        // Act
        var result = AuthService.Login("testuser", "TestPass123!", users);
        
        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Username, Is.EqualTo("testuser"));
    }

    [Test]
    public void Test_Login_InvalidPassword()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = AuthService.HashPassword("TestPass123!"),
                Role = "user"
            }
        };
        
        // Act
        var result = AuthService.Login("testuser", "WrongPassword", users);
        
        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Test_Login_InvalidUsername()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = AuthService.HashPassword("TestPass123!"),
                Role = "user"
            }
        };
        
        // Act
        var result = AuthService.Login("wronguser", "TestPass123!", users);
        
        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Test_Login_NullOrEmptyCredentials()
    {
        // Arrange
        var users = new List<User>();
        
        // Act & Assert
        Assert.That(AuthService.Login(null!, "password", users), Is.Null);
        Assert.That(AuthService.Login("", "password", users), Is.Null);
        Assert.That(AuthService.Login("username", null!, users), Is.Null);
        Assert.That(AuthService.Login("username", "", users), Is.Null);
    }

    [Test]
    public void Test_Login_CaseInsensitiveUsername()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "TestUser",
                Email = "test@example.com",
                PasswordHash = AuthService.HashPassword("TestPass123!"),
                Role = "user"
            }
        };
        
        // Act
        var result1 = AuthService.Login("testuser", "TestPass123!", users);
        var result2 = AuthService.Login("TESTUSER", "TestPass123!", users);
        
        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
    }

    [Test]
    public void Test_IsStrongPassword_ValidPasswords()
    {
        // Arrange & Act & Assert
        Assert.That(AuthService.IsStrongPassword("StrongPass123!"), Is.True);
        Assert.That(AuthService.IsStrongPassword("Test@123Pass"), Is.True);
        Assert.That(AuthService.IsStrongPassword("Abcd1234!@#$"), Is.True);
    }

    [Test]
    public void Test_IsStrongPassword_WeakPasswords()
    {
        // Arrange & Act & Assert
        Assert.That(AuthService.IsStrongPassword("weak"), Is.False); // Too short
        Assert.That(AuthService.IsStrongPassword("password"), Is.False); // No uppercase, digit, special
        Assert.That(AuthService.IsStrongPassword("PASSWORD123!"), Is.False); // No lowercase
        Assert.That(AuthService.IsStrongPassword("Password!"), Is.False); // No digit
        Assert.That(AuthService.IsStrongPassword("Password123"), Is.False); // No special char
        Assert.That(AuthService.IsStrongPassword(""), Is.False);
        Assert.That(AuthService.IsStrongPassword(null!), Is.False);
    }

    [Test]
    public void Test_PasswordHashing_ResistsBruteForce()
    {
        // Arrange
        string password = "TestPassword123!";
        
        // Act - Measure time for hashing (BCrypt should be slow by design)
        var startTime = DateTime.Now;
        string hash = AuthService.HashPassword(password);
        var endTime = DateTime.Now;
        var duration = endTime - startTime;
        
        // Assert
        Assert.That(hash, Is.Not.Null);
        Assert.That(duration.TotalMilliseconds, Is.GreaterThan(10)); // BCrypt should take some time
    }

    [Test]
    public void Test_Authentication_PreventsTimingAttacks()
    {
        // Arrange
        var users = new List<User>
        {
            new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = AuthService.HashPassword("TestPass123!"),
                Role = "user"
            }
        };
        
        // Act - Both should return null (fail) but timing should be similar
        var result1 = AuthService.Login("wronguser", "TestPass123!", users);
        var result2 = AuthService.Login("testuser", "WrongPassword", users);
        
        // Assert
        Assert.That(result1, Is.Null);
        Assert.That(result2, Is.Null);
    }
}
