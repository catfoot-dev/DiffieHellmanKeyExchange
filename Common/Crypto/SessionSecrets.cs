namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// 세션 공유 비밀에서 파생한 방향별 AES 키와 nonce prefix를 보관합니다.
/// </summary>
/// <param name="ClientToServerKey">클라이언트가 서버로 보내는 메시지 암호화에 사용하는 AES 키입니다.</param>
/// <param name="ServerToClientKey">서버가 클라이언트로 보내는 메시지 암호화에 사용하는 AES 키입니다.</param>
/// <param name="ClientToServerNoncePrefix">클라이언트에서 서버로 가는 nonce를 만들 때 앞부분에 붙는 prefix입니다.</param>
/// <param name="ServerToClientNoncePrefix">서버에서 클라이언트로 가는 nonce를 만들 때 앞부분에 붙는 prefix입니다.</param>
public sealed record SessionSecrets(
    byte[] ClientToServerKey,
    byte[] ServerToClientKey,
    byte[] ClientToServerNoncePrefix,
    byte[] ServerToClientNoncePrefix);
