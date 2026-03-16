using System.Text.Json;

namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// 프로토콜 요청과 응답을 직렬화할 때 공유하는 JSON 옵션을 제공합니다.
/// </summary>
public static class ProtocolJson
{
    public static JsonSerializerOptions SerializerOptions { get; } = new(JsonSerializerDefaults.Web);
}
