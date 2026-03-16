using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 단일 세션의 만료 시각, 방향별 sequence, 세션 비밀을 관리하는 상태 객체입니다.
/// </summary>
public sealed class SessionState
{
    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private ulong _lastClientSequence;
    private ulong _lastServerSequence;

    /// <summary>
    /// 세션 식별자와 비밀 재료를 받아 새 세션 상태를 생성합니다.
    /// </summary>
    /// <param name="sessionId">클라이언트와 서버가 함께 사용하는 세션 식별자입니다.</param>
    /// <param name="expiresAtUtc">세션이 더 이상 유효하지 않게 되는 UTC 시각입니다.</param>
    /// <param name="sessionSecrets">암복호화에 사용할 방향별 키 재료입니다.</param>
    /// <param name="timeProvider">세션 만료 여부를 계산할 시간 공급자입니다.</param>
    public SessionState(string sessionId, DateTimeOffset expiresAtUtc, SessionSecrets sessionSecrets, TimeProvider timeProvider)
    {
        SessionId = sessionId;
        ExpiresAtUtc = expiresAtUtc;
        SessionSecrets = sessionSecrets;
        _timeProvider = timeProvider;
    }

    public string SessionId { get; }

    public DateTimeOffset ExpiresAtUtc { get; }

    public SessionSecrets SessionSecrets { get; }

    /// <summary>
    /// 현재 시각 기준으로 세션이 만료되었는지 확인합니다.
    /// </summary>
    /// <returns>현재 시각이 세션 만료 시각 이상이면 <see langword="true"/>입니다.</returns>
    public bool IsExpired() => _timeProvider.GetUtcNow() >= ExpiresAtUtc;

    /// <summary>
    /// 클라이언트 요청 envelope를 복호화하고 요청 방향 sequence를 전진시킵니다.
    /// </summary>
    /// <typeparam name="TPayload">복호화 후 기대하는 payload 형식입니다.</typeparam>
    /// <param name="envelope">클라이언트가 전송한 암호화 요청 envelope입니다.</param>
    /// <returns>복호화된 payload 인스턴스입니다.</returns>
    public TPayload DecryptClientPayload<TPayload>(EncryptedEnvelope envelope)
    {
        lock (_gate)
        {
            EnsureActive();
            ValidateIncomingSequence(envelope.Sequence);

            var payload = ProtocolCrypto.DecryptJson<TPayload>(
                envelope,
                SessionSecrets,
                SessionDirection.ClientToServer);

            _lastClientSequence = envelope.Sequence;
            return payload;
        }
    }

    /// <summary>
    /// 서버 응답 payload를 암호화하고 응답 방향 sequence를 전진시킵니다.
    /// </summary>
    /// <typeparam name="TPayload">암호화할 응답 payload 형식입니다.</typeparam>
    /// <param name="payload">클라이언트에 보낼 응답 payload입니다.</param>
    /// <returns>세션 sequence가 반영된 암호화 envelope입니다.</returns>
    public EncryptedEnvelope EncryptServerPayload<TPayload>(TPayload payload)
    {
        lock (_gate)
        {
            EnsureActive();

            var nextSequence = checked(_lastServerSequence + 1);
            var envelope = ProtocolCrypto.EncryptJson(
                payload,
                SessionId,
                nextSequence,
                SessionSecrets,
                SessionDirection.ServerToClient);

            _lastServerSequence = nextSequence;
            return envelope;
        }
    }

    /// <summary>
    /// 세션이 만료되지 않았는지 확인하고, 만료된 경우 적절한 프로토콜 예외를 발생시킵니다.
    /// </summary>
    private void EnsureActive()
    {
        if (IsExpired())
        {
            throw new ProtocolFailureException(
                StatusCodes.Status410Gone,
                "Session expired",
                "The encrypted session is no longer active.");
        }
    }

    /// <summary>
    /// 수신 sequence가 1부터 시작해 strictly increasing 규칙을 지키는지 검증합니다.
    /// </summary>
    /// <param name="sequence">검증할 클라이언트 요청 sequence 값입니다.</param>
    private void ValidateIncomingSequence(ulong sequence)
    {
        if (sequence == 0)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid sequence",
                "Sequence values must start at 1.");
        }

        if (sequence <= _lastClientSequence)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status409Conflict,
                "Replay detected",
                "The incoming sequence was already processed.");
        }

        if (sequence != _lastClientSequence + 1)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status409Conflict,
                "Sequence out of order",
                "The incoming sequence did not match the expected next value.");
        }
    }
}
