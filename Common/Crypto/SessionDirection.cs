namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// 세션 키와 nonce를 어떤 방향의 메시지에 사용할지 나타냅니다.
/// </summary>
public enum SessionDirection
{
    /// <summary>
    /// 클라이언트에서 서버로 전송되는 요청 방향입니다.
    /// </summary>
    ClientToServer,

    /// <summary>
    /// 서버에서 클라이언트로 전송되는 응답 방향입니다.
    /// </summary>
    ServerToClient
}
