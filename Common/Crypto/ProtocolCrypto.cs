using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DiffieHellmanDemo.Common.Contracts;

namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// ECDH 세션 비밀 파생과 AES-GCM 기반 envelope 암복호화를 담당하는 프로토콜 암호화 유틸리티입니다.
/// </summary>
public static class ProtocolCrypto
{
    private const int AesKeySize = 32;
    private const int NoncePrefixSize = 4;
    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;

    /// <summary>
    /// 세션 핸드셰이크에 사용할 P-256 기반 임시 ECDH 키 쌍을 생성합니다.
    /// </summary>
    /// <returns>공개키 export와 공유 비밀 파생에 사용할 <see cref="ECDiffieHellman"/> 인스턴스입니다.</returns>
    public static ECDiffieHellman CreateEphemeralKey() =>
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>
    /// 로컬 ECDH 키의 공개 부분을 SubjectPublicKeyInfo 형식으로 export한 뒤 Base64 문자열로 변환합니다.
    /// </summary>
    /// <param name="keyAgreement">공개키를 내보낼 ECDH 키 쌍입니다.</param>
    /// <returns>네트워크로 전달 가능한 Base64 인코딩 공개키 문자열입니다.</returns>
    public static string ExportPublicKeyBase64(ECDiffieHellman keyAgreement) =>
        Convert.ToBase64String(keyAgreement.ExportSubjectPublicKeyInfo());

    /// <summary>
    /// 로컬 ECDH 키와 원격 공개키를 이용해 세션용 방향별 키와 nonce prefix를 파생합니다.
    /// </summary>
    /// <param name="localKeyAgreement">공유 비밀을 계산할 로컬 ECDH 키 쌍입니다.</param>
    /// <param name="remotePublicKeyBase64">원격 측이 전송한 Base64 인코딩 공개키입니다.</param>
    /// <returns>요청 방향과 응답 방향에 사용할 세션 비밀 묶음입니다.</returns>
    public static SessionSecrets DeriveSessionSecrets(
        ECDiffieHellman localKeyAgreement,
        string remotePublicKeyBase64)
    {
        var sharedSecret = DeriveSharedSecret(localKeyAgreement, remotePublicKeyBase64);
        return DeriveSessionSecrets(sharedSecret);
    }

    /// <summary>
    /// 이미 계산된 공유 비밀에서 방향별 AES 키와 nonce prefix를 파생합니다.
    /// </summary>
    /// <param name="sharedSecret">ECDH 계산 결과로 얻은 원시 공유 비밀 바이트입니다.</param>
    /// <returns>클라이언트-서버 양방향 통신에 사용할 세션 비밀 묶음입니다.</returns>
    public static SessionSecrets DeriveSessionSecrets(byte[] sharedSecret) =>
        new(
            DeriveLabel(sharedSecret, ProtocolConstants.ClientToServerKeyLabel, AesKeySize),
            DeriveLabel(sharedSecret, ProtocolConstants.ServerToClientKeyLabel, AesKeySize),
            DeriveLabel(sharedSecret, ProtocolConstants.ClientToServerNonceLabel, NoncePrefixSize),
            DeriveLabel(sharedSecret, ProtocolConstants.ServerToClientNonceLabel, NoncePrefixSize));

    /// <summary>
    /// 지정한 세션 정보와 방향에 맞춰 payload를 JSON으로 직렬화한 뒤 AES-GCM envelope로 암호화합니다.
    /// </summary>
    /// <typeparam name="TPayload">JSON으로 직렬화할 payload 형식입니다.</typeparam>
    /// <param name="payload">암호화할 비즈니스 payload입니다.</param>
    /// <param name="sessionId">AAD와 envelope에 함께 포함할 세션 식별자입니다.</param>
    /// <param name="sequence">재전송 방지와 nonce 파생에 사용하는 단조 증가 sequence 값입니다.</param>
    /// <param name="sessionSecrets">세션 공유 비밀에서 파생한 방향별 키 재료입니다.</param>
    /// <param name="direction">현재 payload가 요청인지 응답인지 나타내는 전송 방향입니다.</param>
    /// <returns>암호문, 태그, 세션 정보를 담은 <see cref="EncryptedEnvelope"/>입니다.</returns>
    public static EncryptedEnvelope EncryptJson<TPayload>(
        TPayload payload,
        string sessionId,
        ulong sequence,
        SessionSecrets sessionSecrets,
        SessionDirection direction)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload, ProtocolJson.SerializerOptions);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesTagSize];
        var nonce = BuildNonce(sessionSecrets, direction, sequence);
        var associatedData = BuildAssociatedData(sessionId, sequence, direction);
        var key = GetDirectionKey(sessionSecrets, direction);

        using var aesGcm = new AesGcm(key, AesTagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new EncryptedEnvelope
        {
            SessionId = sessionId,
            Sequence = sequence,
            CiphertextBase64 = Convert.ToBase64String(ciphertext),
            TagBase64 = Convert.ToBase64String(tag)
        };
    }

    /// <summary>
    /// 지정한 방향과 sequence에 맞는 AES-GCM nonce를 생성합니다.
    /// </summary>
    /// <param name="sessionSecrets">세션별 방향 키와 nonce prefix입니다.</param>
    /// <param name="direction">nonce를 생성할 메시지 방향입니다.</param>
    /// <param name="sequence">nonce 뒤쪽 8바이트에 기록할 sequence 값입니다.</param>
    /// <returns>패킷 덤프나 암호화에 사용할 12바이트 nonce 배열입니다.</returns>
    public static byte[] BuildPacketNonce(
        SessionSecrets sessionSecrets,
        SessionDirection direction,
        ulong sequence) =>
        BuildNonce(sessionSecrets, direction, sequence);

    /// <summary>
    /// 수신한 암호화 envelope를 복호화하고 지정한 형식의 JSON payload로 역직렬화합니다.
    /// </summary>
    /// <typeparam name="TPayload">복호화 후 역직렬화할 payload 형식입니다.</typeparam>
    /// <param name="envelope">세션 정보와 암호문을 담은 수신 envelope입니다.</param>
    /// <param name="sessionSecrets">해당 세션에 대해 파생된 방향별 키 재료입니다.</param>
    /// <param name="direction">현재 envelope가 어떤 전송 방향의 키를 사용했는지 나타냅니다.</param>
    /// <returns>복호화 후 역직렬화된 payload 인스턴스입니다.</returns>
    public static TPayload DecryptJson<TPayload>(
        EncryptedEnvelope envelope,
        SessionSecrets sessionSecrets,
        SessionDirection direction)
    {
        var ciphertext = Convert.FromBase64String(envelope.CiphertextBase64);
        var tag = Convert.FromBase64String(envelope.TagBase64);
        var plaintext = new byte[ciphertext.Length];
        var nonce = BuildNonce(sessionSecrets, direction, envelope.Sequence);
        var associatedData = BuildAssociatedData(envelope.SessionId, envelope.Sequence, direction);
        var key = GetDirectionKey(sessionSecrets, direction);

        using var aesGcm = new AesGcm(key, AesTagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return JsonSerializer.Deserialize<TPayload>(plaintext, ProtocolJson.SerializerOptions)
            ?? throw new JsonException("Encrypted payload could not be deserialized.");
    }

    /// <summary>
    /// 로컬 ECDH 키와 원격 공개키를 사용해 원시 공유 비밀을 계산합니다.
    /// </summary>
    /// <param name="localKeyAgreement">공유 비밀 계산에 사용할 로컬 ECDH 키 쌍입니다.</param>
    /// <param name="remotePublicKeyBase64">Base64 인코딩된 원격 공개키입니다.</param>
    /// <returns>SHA-256 기반 파생을 거친 공유 비밀 바이트 배열입니다.</returns>
    private static byte[] DeriveSharedSecret(
        ECDiffieHellman localKeyAgreement,
        string remotePublicKeyBase64)
    {
        var remotePublicKeyBytes = Convert.FromBase64String(remotePublicKeyBase64);

        using var remoteKey = ECDiffieHellman.Create();
        remoteKey.ImportSubjectPublicKeyInfo(remotePublicKeyBytes, out _);

        return localKeyAgreement.DeriveKeyFromHash(remoteKey.PublicKey, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// 공유 비밀과 라벨 문자열을 사용해 지정된 길이의 키 재료를 파생합니다.
    /// </summary>
    /// <param name="sharedSecret">세션별 공유 비밀 바이트입니다.</param>
    /// <param name="label">서로 다른 용도의 키를 분리하기 위한 라벨 문자열입니다.</param>
    /// <param name="length">반환할 바이트 배열의 길이입니다.</param>
    /// <returns>지정한 길이만큼 잘라낸 파생 키 재료입니다.</returns>
    private static byte[] DeriveLabel(byte[] sharedSecret, string label, int length)
    {
        var material = HMACSHA256.HashData(sharedSecret, Encoding.UTF8.GetBytes(label));
        return material.AsSpan(0, length).ToArray();
    }

    /// <summary>
    /// 방향별 nonce prefix와 sequence를 결합해 AES-GCM에서 사용할 12바이트 nonce를 만듭니다.
    /// </summary>
    /// <param name="sessionSecrets">세션별 방향 키와 nonce prefix입니다.</param>
    /// <param name="direction">nonce를 생성할 메시지 방향입니다.</param>
    /// <param name="sequence">nonce 뒤쪽 8바이트에 기록할 sequence 값입니다.</param>
    /// <returns>해당 메시지에만 사용해야 하는 AES-GCM nonce 바이트 배열입니다.</returns>
    private static byte[] BuildNonce(
        SessionSecrets sessionSecrets,
        SessionDirection direction,
        ulong sequence)
    {
        var nonce = new byte[AesNonceSize];
        var prefix = direction == SessionDirection.ClientToServer
            ? sessionSecrets.ClientToServerNoncePrefix
            : sessionSecrets.ServerToClientNoncePrefix;

        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(NoncePrefixSize), sequence);
        return nonce;
    }

    /// <summary>
    /// 세션 식별자, sequence, 방향 정보를 결합한 AAD를 생성합니다.
    /// </summary>
    /// <param name="sessionId">메시지가 속한 세션 식별자입니다.</param>
    /// <param name="sequence">재전송 방지와 무결성 검증에 사용하는 sequence 값입니다.</param>
    /// <param name="direction">메시지의 전송 방향입니다.</param>
    /// <returns>암호문과 함께 인증되는 AAD 바이트 배열입니다.</returns>
    private static byte[] BuildAssociatedData(
        string sessionId,
        ulong sequence,
        SessionDirection direction) =>
        Encoding.UTF8.GetBytes($"{sessionId}:{sequence}:{direction}");

    /// <summary>
    /// 메시지 방향에 맞는 AES 키를 선택합니다.
    /// </summary>
    /// <param name="sessionSecrets">세션별 방향 키 집합입니다.</param>
    /// <param name="direction">선택할 키의 전송 방향입니다.</param>
    /// <returns>지정한 방향에 대응하는 AES 키 바이트 배열입니다.</returns>
    private static byte[] GetDirectionKey(SessionSecrets sessionSecrets, SessionDirection direction) =>
        direction == SessionDirection.ClientToServer
            ? sessionSecrets.ClientToServerKey
            : sessionSecrets.ServerToClientKey;
}
