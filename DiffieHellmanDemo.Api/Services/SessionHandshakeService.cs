using System.Security.Cryptography;
using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Api.Services;

/// <summary>
/// 핸드셰이크 요청을 검증하고 세션 비밀과 응답 DTO를 생성합니다.
/// </summary>
public sealed class SessionHandshakeService
{
    private readonly SessionStore _sessionStore;

    /// <summary>
    /// 세션 등록에 사용할 저장소를 받아 핸드셰이크 서비스를 초기화합니다.
    /// </summary>
    /// <param name="sessionStore">생성된 세션을 등록할 저장소입니다.</param>
    public SessionHandshakeService(SessionStore sessionStore)
    {
        _sessionStore = sessionStore;
    }

    /// <summary>
    /// 클라이언트 공개키를 검증하고 서버 공개키 및 세션 식별자를 담은 핸드셰이크 응답을 생성합니다.
    /// </summary>
    /// <param name="request">클라이언트 공개키가 담긴 핸드셰이크 요청입니다.</param>
    /// <returns>새 세션 정보와 서버 공개키를 포함한 핸드셰이크 응답입니다.</returns>
    public HandshakeResponse CreateHandshake(HandshakeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ClientPublicKeyBase64))
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid handshake request",
                "The client public key is required.");
        }

        try
        {
            using var serverKeyAgreement = ProtocolCrypto.CreateEphemeralKey();
            var sessionSecrets = ProtocolCrypto.DeriveSessionSecrets(serverKeyAgreement, request.ClientPublicKeyBase64);
            var session = _sessionStore.CreateSession(sessionSecrets);

            return new HandshakeResponse
            {
                SessionId = session.SessionId,
                ServerPublicKeyBase64 = ProtocolCrypto.ExportPublicKeyBase64(serverKeyAgreement),
                ExpiresAtUtc = session.ExpiresAtUtc.ToUnixTimeMilliseconds(),
                Algorithm = ProtocolConstants.AlgorithmName
            };
        }
        catch (FormatException ex)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid handshake request",
                $"The client public key was not valid base64. {ex.Message}");
        }
        catch (CryptographicException ex)
        {
            throw new ProtocolFailureException(
                StatusCodes.Status400BadRequest,
                "Invalid handshake request",
                $"The client public key could not be imported. {ex.Message}");
        }
    }
}
