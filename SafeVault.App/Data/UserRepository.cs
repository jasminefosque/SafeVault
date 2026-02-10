using System.Data;
using System.Data.Common;
using SafeVault.App.Models;
using SafeVault.App.Security;

namespace SafeVault.App.Data;

/// <summary>
/// Repository for User data access using parameterized SQL queries to prevent SQL injection
/// </summary>
public class UserRepository
{
    private readonly DbConnection _connection;

    public UserRepository(DbConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
    }

    /// <summary>
    /// Creates a new user with sanitized input and parameterized query
    /// </summary>
    public int CreateUser(string username, string email, string password, string role = "user")
    {
        // Validate and sanitize inputs
        if (!InputSanitizer.IsValidUsername(username))
            throw new ArgumentException("Invalid username format", nameof(username));

        if (!InputSanitizer.IsValidEmail(email))
            throw new ArgumentException("Invalid email format", nameof(email));

        if (!AuthService.IsStrongPassword(password))
            throw new ArgumentException("Password does not meet security requirements", nameof(password));

        // Hash password
        string passwordHash = AuthService.HashPassword(password);

        // Use parameterized query to prevent SQL injection
        string query = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES (@Username, @Email, @PasswordHash, @Role);
            SELECT last_insert_rowid();";

        using var command = _connection.CreateCommand();
        command.CommandText = query;

        AddParameter(command, "@Username", username);
        AddParameter(command, "@Email", email);
        AddParameter(command, "@PasswordHash", passwordHash);
        AddParameter(command, "@Role", role);

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        var result = command.ExecuteScalar();
        return Convert.ToInt32(result);
    }

    /// <summary>
    /// Gets a user by username using parameterized query
    /// </summary>
    public User? GetUserByUsername(string username)
    {
        if (string.IsNullOrEmpty(username))
            return null;

        // Use parameterized query to prevent SQL injection
        string query = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Username = @Username";

        using var command = _connection.CreateCommand();
        command.CommandText = query;
        AddParameter(command, "@Username", username);

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return new User
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                Role = reader.GetString(4)
            };
        }

        return null;
    }

    /// <summary>
    /// Gets a user by ID using parameterized query
    /// </summary>
    public User? GetUserById(int id)
    {
        // Use parameterized query to prevent SQL injection
        string query = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Id = @Id";

        using var command = _connection.CreateCommand();
        command.CommandText = query;
        AddParameter(command, "@Id", id);

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return new User
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                Role = reader.GetString(4)
            };
        }

        return null;
    }

    /// <summary>
    /// Updates user role using parameterized query
    /// </summary>
    public bool UpdateUserRole(int userId, string newRole)
    {
        // Use parameterized query to prevent SQL injection
        string query = "UPDATE Users SET Role = @Role WHERE Id = @Id";

        using var command = _connection.CreateCommand();
        command.CommandText = query;
        AddParameter(command, "@Role", newRole);
        AddParameter(command, "@Id", userId);

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        int rowsAffected = command.ExecuteNonQuery();
        return rowsAffected > 0;
    }

    /// <summary>
    /// Deletes a user using parameterized query
    /// </summary>
    public bool DeleteUser(int userId)
    {
        // Use parameterized query to prevent SQL injection
        string query = "DELETE FROM Users WHERE Id = @Id";

        using var command = _connection.CreateCommand();
        command.CommandText = query;
        AddParameter(command, "@Id", userId);

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        int rowsAffected = command.ExecuteNonQuery();
        return rowsAffected > 0;
    }

    /// <summary>
    /// Gets all users using secure query
    /// </summary>
    public List<User> GetAllUsers()
    {
        var users = new List<User>();
        string query = "SELECT Id, Username, Email, PasswordHash, Role FROM Users";

        using var command = _connection.CreateCommand();
        command.CommandText = query;

        if (_connection.State != ConnectionState.Open)
            _connection.Open();

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            users.Add(new User
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                Role = reader.GetString(4)
            });
        }

        return users;
    }

    /// <summary>
    /// Helper method to add parameters safely
    /// </summary>
    private void AddParameter(DbCommand command, string parameterName, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = parameterName;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
