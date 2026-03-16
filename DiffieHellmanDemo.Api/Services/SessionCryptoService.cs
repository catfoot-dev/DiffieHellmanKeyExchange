using System.Security.Cryptography;
using System.Text.Json;
using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 암호화 envelope의 입력 검증, 세션 조회, 복호화/응답 암호화를 조합하는 서비스입니다.
/// </summary>
public sealed class SessionCryptoService
{
    private readonly SessionStore _sessionStore;

    /// <summary>
    /// 세션 조회에 사용할 저장소를 받아 암호화 서비스를 초기화합니다.
    /// </summary>
    /// <param name="sessionStore">세션 식별자로 암호화 상태를 조회할 저장소입니다.</param>
    public SessionCryptoService(SessionStore sessionStore)
    {
        _sessionStore = sessionStore;
    }

    /// <summary>
    /// 클라이언트가 보낸 envelope를 검증하고 현재 세션 기준으로 복호화한 payload를 반환합니다.
    /// </summary>
    /// <typeparam name="TPayload">복호화 후 기대하는 payload 형식입니다.</typeparam>
    /// <param name="envelope">세션 식별자와 암호문을 담은 클라이언트 요청 envelope입니다.</param>
    /// <returns>복호화에 사용한 세션과 역직렬화된 payload를 함께 담은 tuple입니다.</returns>
    public (SessionState Session, TPayload Payload) DecryptClientEnvelope<TPayload>(EncryptedEnvelope envelope)
    {
        ValidateEnvelope(envelope);
        var session = _sessionStore.GetRequired(envelope.SessionId);
        var payload = DecryptClientEnvelope<TPayload>(session, envelope);
        return (session, payload);
    }

    /// <summary>
    /// 이미 조회한 세션 상태를 사용해 클라이언트가 보낸 envelope를 복호화합니다.
    /// </summary>
    /// <typeparam name="TPayload">복호화 후 기대하는 payload 형식입니다.</typeparam>
    /// <param name="session">이미 유효성이 확인된 세션 상태입니다.</param>
    /// <param name="envelope">세션 식별자와 암호문을 담은 클라이언트 요청 envelope입니다.</param>
    /// <returns>역직렬화가 완료된 클라이언트 요청 payload입니다.</returns>
    internal TPayload DecryptClientEnvelope<TPayload>(SessionState session, EncryptedEnvelope envelope)
    {
        ValidateEnvelope(envelope);

        if (!string.Equals(session.SessionId, envelope.SessionId, StringComparison.Ordinal))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                "The envelope session id did not match the resolved session.");
        }

        try
        {
            return session.DecryptClientPayload<TPayload>(envelope);
        }
        catch (ProtocolFailureException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                $"The encrypted envelope could not be decoded. {ex.Message}");
        }
        catch (CryptographicException ex)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                $"The encrypted payload failed authentication. {ex.Message}");
        }
        catch (JsonException ex)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                $"The encrypted payload could not be deserialized. {ex.Message}");
        }
    }

    /// <summary>
    /// 서버에서 보낼 payload를 현재 세션의 응답 방향 키로 암호화합니다.
    /// </summary>
    /// <typeparam name="TPayload">암호화할 응답 payload 형식입니다.</typeparam>
    /// <param name="session">응답 sequence와 키 재료를 보유한 세션 상태입니다.</param>
    /// <param name="payload">암호화할 응답 payload입니다.</param>
    /// <returns>클라이언트에 전송할 암호화 envelope입니다.</returns>
    public EncryptedEnvelope EncryptServerEnvelope<TPayload>(SessionState session, TPayload payload) =>
        session.EncryptServerPayload(payload);

    /// <summary>
    /// envelope에 필수 필드가 모두 존재하는지 선검증합니다.
    /// </summary>
    /// <param name="envelope">검증할 암호화 envelope입니다.</param>
    private static void ValidateEnvelope(EncryptedEnvelope envelope)
    {
        if (string.IsNullOrWhiteSpace(envelope.SessionId))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                "The encrypted envelope must include a session id.");
        }

        if (envelope.Sequence == 0)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                "The encrypted envelope must include a positive sequence.");
        }

        if (string.IsNullOrWhiteSpace(envelope.CiphertextBase64) ||
            string.IsNullOrWhiteSpace(envelope.TagBase64))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid encrypted envelope",
                "The encrypted envelope is missing ciphertext or tag data.");
        }
    }
}
