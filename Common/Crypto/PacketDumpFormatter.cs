using System.Text;
using System.Text.Json;
using DiffieHellmanDemo.Common.Contracts;

namespace DiffieHellmanDemo.Common.Crypto;

/// <summary>
/// CLI에서 표시할 평문 JSON과 암호화 패킷 hex 덤프를 공통 형식으로 생성합니다.
/// </summary>
public static class PacketDumpFormatter
{
    private static readonly JsonSerializerOptions PrettyJsonOptions = new(ProtocolJson.SerializerOptions)
    {
        WriteIndented = true
    };

    /// <summary>
    /// 지정한 payload를 사람이 읽기 쉬운 들여쓰기 JSON 문자열로 변환합니다.
    /// </summary>
    /// <typeparam name="TPayload">JSON으로 직렬화할 payload 형식입니다.</typeparam>
    /// <param name="payload">CLI에 표시할 평문 payload입니다.</param>
    /// <returns>들여쓰기와 줄바꿈이 포함된 JSON 문자열입니다.</returns>
    public static string FormatJson<TPayload>(TPayload payload) =>
        JsonSerializer.Serialize(payload, PrettyJsonOptions);

    /// <summary>
    /// 암호화 envelope를 <c>nonce || ciphertext || tag</c> 순서의 실제 패킷 바이트로 결합합니다.
    /// </summary>
    /// <param name="envelope">세션 식별자와 암호문을 담은 암호화 envelope입니다.</param>
    /// <param name="sessionSecrets">해당 세션에 대한 방향별 키와 nonce prefix입니다.</param>
    /// <param name="direction">패킷이 전송된 방향입니다.</param>
    /// <returns>nonce, ciphertext, tag를 순서대로 이어 붙인 패킷 바이트 배열입니다.</returns>
    public static byte[] BuildEncryptedPacketBytes(
        EncryptedEnvelope envelope,
        SessionSecrets sessionSecrets,
        SessionDirection direction)
    {
        var nonce = ProtocolCrypto.BuildPacketNonce(sessionSecrets, direction, envelope.Sequence);
        var ciphertext = Convert.FromBase64String(envelope.CiphertextBase64);
        var tag = Convert.FromBase64String(envelope.TagBase64);
        var packetBytes = new byte[nonce.Length + ciphertext.Length + tag.Length];

        Buffer.BlockCopy(nonce, 0, packetBytes, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, packetBytes, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, packetBytes, nonce.Length + ciphertext.Length, tag.Length);

        return packetBytes;
    }

    /// <summary>
    /// 암호화 envelope를 CLI 출력용 hex 블록 문자열로 변환합니다.
    /// </summary>
    /// <param name="envelope">세션 식별자와 암호문을 담은 암호화 envelope입니다.</param>
    /// <param name="sessionSecrets">해당 세션에 대한 방향별 키와 nonce prefix입니다.</param>
    /// <param name="direction">패킷이 전송된 방향입니다.</param>
    /// <param name="bytesPerLine">한 줄에 표시할 바이트 수입니다.</param>
    /// <returns><c>nonce || ciphertext || tag</c> 순서로 정렬된 hex 블록 문자열입니다.</returns>
    public static string FormatEncryptedPacketHex(
        EncryptedEnvelope envelope,
        SessionSecrets sessionSecrets,
        SessionDirection direction,
        int bytesPerLine = 16) =>
        FormatHexBlock(BuildEncryptedPacketBytes(envelope, sessionSecrets, direction), bytesPerLine);

    /// <summary>
    /// 암호화 envelope를 hex 블록으로 변환할 수 있는지 시도하고 실패 시 오류 메시지를 반환합니다.
    /// </summary>
    /// <param name="envelope">세션 식별자와 암호문을 담은 암호화 envelope입니다.</param>
    /// <param name="sessionSecrets">해당 세션에 대한 방향별 키와 nonce prefix입니다.</param>
    /// <param name="direction">패킷이 전송된 방향입니다.</param>
    /// <param name="formattedHex">성공 시 생성된 hex 블록 문자열을 반환합니다.</param>
    /// <param name="errorMessage">실패 시 hex 블록을 만들지 못한 이유를 반환합니다.</param>
    /// <returns>hex 블록 생성에 성공하면 <see langword="true"/>입니다.</returns>
    public static bool TryFormatEncryptedPacketHex(
        EncryptedEnvelope envelope,
        SessionSecrets sessionSecrets,
        SessionDirection direction,
        out string formattedHex,
        out string errorMessage)
    {
        try
        {
            formattedHex = FormatEncryptedPacketHex(envelope, sessionSecrets, direction);
            errorMessage = string.Empty;
            return true;
        }
        catch (FormatException ex)
        {
            formattedHex = string.Empty;
            errorMessage = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// 바이트 배열을 고정 폭 줄바꿈이 포함된 hex 텍스트 블록으로 변환합니다.
    /// </summary>
    /// <param name="bytes">hex로 표시할 바이트 배열입니다.</param>
    /// <param name="bytesPerLine">한 줄에 표시할 바이트 수입니다.</param>
    /// <returns>두 자리 대문자 hex와 공백으로 구성된 블록 문자열입니다.</returns>
    public static string FormatHexBlock(byte[] bytes, int bytesPerLine = 16)
    {
        if (bytesPerLine <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bytesPerLine), "bytesPerLine must be positive.");
        }

        var builder = new StringBuilder();

        for (var index = 0; index < bytes.Length; index++)
        {
            // if (index > 0)
            // {
            //     if (index % bytesPerLine == 0)
            //     {
            //         builder.AppendLine();
            //     }
            //     else
            //     {
            //         builder.Append(' ');
            //     }
            // }

            builder.Append(bytes[index].ToString("X2"));
        }

        return builder.ToString();
    }
}
