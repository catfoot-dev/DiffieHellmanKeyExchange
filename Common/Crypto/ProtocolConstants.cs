namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// 데모 프로토콜에서 사용하는 알고리즘 이름, 만료 시간, 라벨 값을 모아 둔 상수 집합입니다.
/// </summary>
public static class ProtocolConstants
{
    public const string AlgorithmName = "ECDH-P256/AES-256-GCM/HMAC-SHA256";
    public static readonly TimeSpan SessionTtl = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan MaxJwtLifetime = TimeSpan.FromMinutes(5);

    public const string ClientToServerKeyLabel = "c2s-aes-key";
    public const string ServerToClientKeyLabel = "s2c-aes-key";
    public const string ClientToServerNonceLabel = "c2s-nonce-prefix";
    public const string ServerToClientNonceLabel = "s2c-nonce-prefix";
}
