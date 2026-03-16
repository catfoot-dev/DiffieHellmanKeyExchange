using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Client;

/// <summary>
/// 클라이언트 측에서 현재 세션의 키 재료와 양방향 sequence 상태를 관리합니다.
/// </summary>
public sealed class ClientSessionState
{
    private ulong _nextClientSequence = 1;
    private ulong _expectedServerSequence = 1;

    /// <summary>
    /// 세션 식별자와 세션 비밀을 받아 클라이언트 세션 상태를 초기화합니다.
    /// </summary>
    /// <param name="sessionId">서버와 공유하는 세션 식별자입니다.</param>
    /// <param name="sessionSecrets">요청/응답 암호화에 사용할 방향별 세션 비밀입니다.</param>
    public ClientSessionState(string sessionId, SessionSecrets sessionSecrets)
    {
        SessionId = sessionId;
        SessionSecrets = sessionSecrets;
    }

    public string SessionId { get; }

    public SessionSecrets SessionSecrets { get; }

    /// <summary>
    /// 클라이언트 요청 payload를 현재 sequence 값으로 암호화하고 다음 sequence를 준비합니다.
    /// </summary>
    /// <typeparam name="TPayload">암호화할 요청 payload 형식입니다.</typeparam>
    /// <param name="payload">서버로 보낼 평문 payload입니다.</param>
    /// <returns>클라이언트-서버 방향 키로 암호화된 envelope입니다.</returns>
    public EncryptedEnvelope EncryptPayload<TPayload>(TPayload payload)
    {
        var sequence = _nextClientSequence;
        var envelope = ProtocolCrypto.EncryptJson(
            payload,
            SessionId,
            sequence,
            SessionSecrets,
            SessionDirection.ClientToServer);

        _nextClientSequence++;
        return envelope;
    }

    /// <summary>
    /// 서버 응답 envelope를 복호화하고 기대 sequence와 세션 식별자를 검증합니다.
    /// </summary>
    /// <typeparam name="TPayload">복호화 후 기대하는 응답 payload 형식입니다.</typeparam>
    /// <param name="envelope">서버가 반환한 암호화 응답 envelope입니다.</param>
    /// <returns>검증과 복호화가 완료된 응답 payload입니다.</returns>
    public TPayload DecryptPayload<TPayload>(EncryptedEnvelope envelope)
    {
        if (!string.Equals(envelope.SessionId, SessionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The response session id did not match the active client session.");
        }

        if (envelope.Sequence != _expectedServerSequence)
        {
            throw new InvalidOperationException(
                $"Expected server sequence {_expectedServerSequence}, but received {envelope.Sequence}.");
        }

        var payload = ProtocolCrypto.DecryptJson<TPayload>(
            envelope,
            SessionSecrets,
            SessionDirection.ServerToClient);

        _expectedServerSequence++;
        return payload;
    }
}
