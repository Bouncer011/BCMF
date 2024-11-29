using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;

public class ServerHandler
{
    private const string AuthUrl = "https://nyanko-auth.ponosgames.com";
    private const string SaveUrl = "https://nyanko-save.ponosgames.com";
    private const string BackupsUrl = "https://nyanko-backups.ponosgames.com";
    private const string AwsUrl = "https://nyanko-service-data-prd.s3.amazonaws.com";
    private const string ManagedItemUrl = "https://nyanko-managed-item.ponosgames.com";

    private readonly HttpClient _httpClient;
    private readonly SaveFile _saveFile;
    private string? _storedPassword;
    private string? _storedAuthToken;
    private Dictionary<string, object>? _storedSaveKey;

    public ServerHandler(SaveFile saveFile)
    {
        _saveFile = saveFile;
        _httpClient = new HttpClient();
    }

    public async Task<(string TransferCode, string ConfirmationCode)?> GetCodesAsync()
    {
        var authToken = await GetAuthTokenAsync();
        if (authToken == null) return null;

        var saveKey = await GetSaveKeyAsync(authToken);
        if (saveKey == null) return null;

        if (!await UploadSaveDataAsync(saveKey)) return null;

        var metaData = CreateBackupMetaData(saveKey["key"].ToString());
        var url = $"{SaveUrl}/v2/transfers";

        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);
        request.Content = new StringContent(metaData, Encoding.UTF8, "application/json");

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!IsSuccessResponse(responseContent)) return null;

        var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        var payload = (JsonElement)responseJson["payload"];

        return (
            payload.GetProperty("transferCode").GetString(),
            payload.GetProperty("pin").GetString()
        );
    }

    private async Task<string?> GetAuthTokenAsync()
    {
        // Check stored auth token
        if (!string.IsNullOrEmpty(_storedAuthToken) && ValidateAuthToken(_storedAuthToken))
            return _storedAuthToken;

        // Get password
        var password = await GetPasswordAsync();
        if (password == null) return null;

        var url = $"{AuthUrl}/v1/tokens";
        var data = new Dictionary<string, string>
        {
            ["password"] = password,
            ["accountCode"] = _saveFile.InquiryCode,
            ["clientType"] = "Android",
            ["clientVersion"] = "11.7.0"
        };

        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(
            JsonSerializer.Serialize(data), 
            Encoding.UTF8, 
            "application/json"
        );

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!IsSuccessResponse(responseContent)) return null;

        var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        var payload = (JsonElement)responseJson["payload"];
        _storedAuthToken = payload.GetProperty("token").GetString();

        return _storedAuthToken;
    }

    private async Task<string?> GetPasswordAsync()
    {
        // Check stored password first
        if (!string.IsNullOrEmpty(_storedPassword)) 
            return _storedPassword;

        // Try to refresh password
        var refreshedPassword = await RefreshPasswordAsync();
        if (refreshedPassword != null) return refreshedPassword;

        // Get new password
        var url = $"{AuthUrl}/v1/users";
        var data = new Dictionary<string, object>
        {
            ["accountCode"] = _saveFile.InquiryCode,
            ["accountCreatedAt"] = _saveFile.EnergyPenaltyTimestamp,
            ["nonce"] = GenerateNonce()
        };

        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(
            JsonSerializer.Serialize(data), 
            Encoding.UTF8, 
            "application/json"
        );

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!IsSuccessResponse(responseContent)) return null;

        var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        var payload = (JsonElement)responseJson["payload"];

        _storedPassword = payload.GetProperty("password").GetString();
        _saveFile.PasswordRefreshToken = payload.GetProperty("passwordRefreshToken").GetString();

        return _storedPassword;
    }

    private async Task<string?> RefreshPasswordAsync()
    {
        if (string.IsNullOrEmpty(_saveFile.PasswordRefreshToken)) return null;

        var url = $"{AuthUrl}/v1/user/password";
        var data = new Dictionary<string, string>
        {
            ["accountCode"] = _saveFile.InquiryCode,
            ["passwordRefreshToken"] = _saveFile.PasswordRefreshToken,
            ["nonce"] = GenerateNonce()
        };

        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(
            JsonSerializer.Serialize(data), 
            Encoding.UTF8, 
            "application/json"
        );

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!IsSuccessResponse(responseContent)) return null;

        var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        var payload = (JsonElement)responseJson["payload"];

        _storedPassword = payload.GetProperty("password").GetString();
        _saveFile.PasswordRefreshToken = payload.GetProperty("passwordRefreshToken").GetString();

        return _storedPassword;
    }

    private async Task<Dictionary<string, object>?> GetSaveKeyAsync(string authToken)
    {
        // Check stored save key
        if (_storedSaveKey != null) return _storedSaveKey;

        var nonce = GenerateNonce();
        var url = $"{SaveUrl}/v2/save/key?nonce={nonce}";

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);
        request.Headers.Add("nyanko-timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!IsSuccessResponse(responseContent)) return null;

        var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
        _storedSaveKey = (Dictionary<string, object>)((JsonElement)responseJson["payload"]).EnumerateObject()
            .ToDictionary(p => p.Name, p => (object)p.Value.ToString());

        return _storedSaveKey;
    }

    private async Task<bool> UploadSaveDataAsync(Dictionary<string, object> saveKey)
    {
        var boundary = $"---------------------------{GenerateNonce()}";
        var saveData = _saveFile.ToByteArray();

        var multipartContent = new MultipartFormDataContent(boundary);

        // Add save key parameters
        var requiredKeys = new[] { "key", "policy", "x-amz-signature", "x-amz-credential", "x-amz-algorithm", "x-amz-date", "x-amz-security-token" };
        foreach (var key in requiredKeys)
        {
            if (saveKey.TryGetValue(key, out var value))
            {
                multipartContent.Add(new StringContent(value.ToString()), key);
            }
        }

        // Add save file
        var fileContent = new ByteArrayContent(saveData);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        multipartContent.Add(fileContent, "file", "file.sav");

        var request = new HttpRequestMessage(HttpMethod.Post, AwsUrl)
        {
            Content = multipartContent
        };

        var response = await _httpClient.SendAsync(request);
        return response.IsSuccessStatusCode;
    }

    private string CreateBackupMetaData(string saveKey)
    {
        var metaData = new Dictionary<string, object>
        {
            ["clientType"] = "Android",
            ["clientVersion"] = "11.7.0",
            ["saveKey"] = saveKey
        };
        return JsonSerializer.Serialize(metaData);
    }

    private static bool IsSuccessResponse(string responseContent)
    {
        try
        {
            var responseJson = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
            var statusCode = ((JsonElement)responseJson["statusCode"]).GetInt32();
            return statusCode == 1;
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateAuthToken(string authToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(authToken) as JwtSecurityToken;

            if (jsonToken == null) return false;

            // Check expiration
            if (jsonToken.ValidTo < DateTime.UtcNow) return false;

            // Check account code
            var accountClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "accountCode");
            return accountClaim?.Value == _saveFile.InquiryCode;
        }
        catch
        {
            return false;
        }
    }

    private static string GenerateNonce()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))
            .Replace("+", "")
            .Replace("/", "")
            .Replace("=", "")
            .Substring(0, 32);
    }

    public static async Task<SaveFile?> FromCodesAsync(
        string transferCode, 
        string confirmationCode)
    {
        var url = $"{SaveUrl}/v2/transfers/{transferCode}/reception";
        var httpClient = new HttpClient();

        var data = new Dictionary<string, string>
        {
            ["pin"] = confirmationCode,
            ["clientType"] = "Android",
            ["clientVersion"] = "11.7.0"
        };

        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(
            JsonSerializer.Serialize(data), 
            Encoding.UTF8, 
            "application/json"
        );

        var response = await httpClient.SendAsync(request);
        
        if (!response.IsSuccessStatusCode) return null;

        var saveData = await response.Content.ReadAsByteArrayAsync();
        return new SaveFile(saveData);
    }
}

public class SaveFile
{
    public string InquiryCode { get; set; }
    public long EnergyPenaltyTimestamp { get; set; }
    public string PasswordRefreshToken { get; set; }
    public bool ShowBanMessage { get; set; } = true;
    public int Catfood { get; set; }
    public int LegendTickets { get; set; }
    public int PlatinumTickets { get; set; }
    public int RareTickets { get; set; }

    private byte[] _saveData;

    public SaveFile(byte[] saveData)
    {
        _saveData = saveData;
        // Not Finished
        // Adding Inquery code and Timestamp parsing later
    }

    public byte[] ToByteArray() => _saveData;

    // Methods to store and retrieve strings
    private Dictionary<string, string> _storedStrings = new Dictionary<string, string>();
    
    public void StoreString(string key, string value)
    {
        _storedStrings[key] = value;
    }

    public string GetString(string key)
    {
        return _storedStrings.TryGetValue(key, out var value) ? value : null;
    }

    public void RemoveString(string key)
    {
        _storedStrings.Remove(key);
    }

    // Methods to store and retrieve dictionaries
    private Dictionary<string, Dictionary<string, object>> _storedDictionaries = new Dictionary<string, Dictionary<string, object>>();

    public void StoreDictionary(string key, Dictionary<string, object> value)
    {
        _storedDictionaries[key] = value;
    }

    public Dictionary<string, object> GetDictionary(string key)
    {
        return _storedDictionaries.TryGetValue(key, out var value) ? value : null;
    }

    public void RemoveDictionary(string key)
    {
        _storedDictionaries.Remove(key);
    }
}
