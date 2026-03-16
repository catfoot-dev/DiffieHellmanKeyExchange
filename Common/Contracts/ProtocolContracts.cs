namespace DiffieHellmanDemo.Common.Contracts;

/// <summary>
/// 클라이언트가 자신의 ECDH 공개키를 서버에 전달할 때 사용하는 핸드셰이크 요청 모델입니다.
/// </summary>
public sealed record HandshakeRequest
{
    public required string ClientPublicKeyBase64 { get; init; }
}

/// <summary>
/// 서버가 세션 식별자와 자신의 공개키를 반환할 때 사용하는 핸드셰이크 응답 모델입니다.
/// </summary>
public sealed record HandshakeResponse
{
    public required string SessionId { get; init; }

    public required string ServerPublicKeyBase64 { get; init; }

    public required long ExpiresAtUtc { get; init; }

    public required string Algorithm { get; init; }
}

/// <summary>
/// 세션 식별자와 sequence, 인증된 암호문을 함께 전달하는 앱 레벨 암호화 envelope입니다.
/// </summary>
public sealed record EncryptedEnvelope
{
    public required string SessionId { get; init; }

    public required ulong Sequence { get; init; }

    public required string CiphertextBase64 { get; init; }

    public required string TagBase64 { get; init; }
}

/// <summary>
/// 암호화된 로그인 요청 내부에 실리는 사용자 자격 증명입니다.
/// </summary>
public sealed record LoginPayload
{
    public required string Username { get; init; }

    public required string Password { get; init; }
}

/// <summary>
/// 암호화된 로그인 응답 내부에 실리는 JWT 발급 결과입니다.
/// </summary>
public sealed record LoginResult
{
    public required string AccessToken { get; init; }

    public required long ExpiresAtUtc { get; init; }

    public required string UserName { get; init; }
}

/// <summary>
/// 보호된 echo 호출에서 서버에 되돌려 달라고 요청하는 메시지입니다.
/// </summary>
public sealed record EchoPayload
{
    public required string Message { get; init; }
}

/// <summary>
/// 보호된 echo 호출의 복호화 결과를 담는 응답 모델입니다.
/// </summary>
public sealed record EchoResult
{
    public required string EchoedMessage { get; init; }

    public required string UserName { get; init; }

    public required long ServerTimeUtc { get; init; }
}
