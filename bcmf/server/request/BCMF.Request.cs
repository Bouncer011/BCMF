using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace BCMF.Request
{
    public class RequestHandler
    {
        private readonly string _url;
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _serializerOptions;

        public RequestHandler(string url, HttpRequestMessage? headers = null)
        {
            _url = url ?? throw new ArgumentNullException(nameof(url));
            _httpClient = new HttpClient();
            _serializerOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };

            if (headers != null)
            {
                foreach (var header in headers.Headers)
                {
                    _httpClient.DefaultRequestHeaders.Add(header.Key, string.Join(",", header.Value));
                }
            }
        }

        public async Task<HttpResponseMessage?> GetAsync(bool stream = false)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, _url)
                {
                    Version = HttpVersion.Version20
                };

                if (stream)
                {
                    request.Headers.Add("Accept", "application/octet-stream");
                }

                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"GET request failed: {ex.Message}");
                return null;
            }
        }

        public async Task<HttpResponseMessage?> PostAsync<T>(T data) where T : class
        {
            try
            {
                var content = JsonSerializer.Serialize(data, _serializerOptions);
                var requestContent = new StringContent(content, System.Text.Encoding.UTF8, "application/json");

                return await _httpClient.PostAsync(_url, requestContent).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"POST request failed: {ex.Message}");
                return null;
            }
        }
    }
}
