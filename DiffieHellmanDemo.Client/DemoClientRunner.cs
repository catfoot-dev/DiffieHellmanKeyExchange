using System.Net.Http.Headers;
using System.Net.Http.Json;
using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;

namespace DiffieHellmanDemo.Client;

/// <summary>
/// 핸드셰이크, 암호화 로그인, 보호된 API 호출을 순서대로 실행하는 CLI 데모 오케스트레이터입니다.
/// </summary>
public static class DemoClientRunner
{
    private static readonly Uri DefaultServerUri = new("http://localhost:8080");

    /// <summary>
    /// interactive 입력을 사용해 핸드셰이크, 로그인, 반복 echo 루프까지 전체 데모를 실행합니다.
    /// </summary>
    /// <param name="cancellationToken">HTTP 호출과 비동기 흐름을 취소할 때 사용하는 토큰입니다.</param>
    /// <returns>데모 실행 완료를 나타내는 작업입니다.</returns>
    public static Task RunAsync(CancellationToken cancellationToken = default)
    {
        var reporter = new ClientProgressReporter();
        var promptInput = new ClientPromptInput(new SystemClientConsole(), reporter);
        return RunAsync(reporter, promptInput, cancellationToken);
    }

    /// <summary>
    /// 지정한 reporter와 프롬프트 입력기를 사용해 전체 암호화 프로토콜 데모를 실행합니다.
    /// </summary>
    /// <param name="reporter">진행상태를 서버 형식과 같은 콘솔 로그로 출력하는 클라이언트 출력기입니다.</param>
    /// <param name="promptInput">자격 증명, 단계 진행, echo 메시지를 수집하는 프롬프트 도우미입니다.</param>
    /// <param name="cancellationToken">HTTP 호출과 비동기 흐름을 취소할 때 사용하는 토큰입니다.</param>
    /// <returns>데모 실행 완료를 나타내는 작업입니다.</returns>
    private static async Task RunAsync(
        ClientProgressReporter reporter,
        ClientPromptInput promptInput,
        CancellationToken cancellationToken)
    {
        using var httpClient = new HttpClient
        {
            BaseAddress = DefaultServerUri
        };

        reporter.ReportStep(
            "client",
            1,
            "클라이언트 데모를 시작합니다.",
            $"서버: {DefaultServerUri}");

        var credentials = promptInput.PromptForCredentials();

        using var clientKeyAgreement = ProtocolCrypto.CreateEphemeralKey();
        var handshakeRequest = new HandshakeRequest
        {
            ClientPublicKeyBase64 = ProtocolCrypto.ExportPublicKeyBase64(clientKeyAgreement)
        };

        reporter.ReportStep(
            "handshake",
            1,
            "핸드셰이크 요청 패킷을 전송합니다.",
            "요청 JSON:",
            PacketDumpFormatter.FormatJson(handshakeRequest));

        var handshakeResponse = await PostJsonAsync<HandshakeRequest, HandshakeResponse>(
            httpClient,
            "/api/session/handshake",
            handshakeRequest,
            cancellationToken);

        var sessionSecrets = ProtocolCrypto.DeriveSessionSecrets(
            clientKeyAgreement,
            handshakeResponse.ServerPublicKeyBase64);
        var session = new ClientSessionState(handshakeResponse.SessionId, sessionSecrets);

        reporter.ReportStep(
            "handshake",
            2,
            "핸드셰이크 응답 패킷을 수신했습니다.",
            $"세션: {ShortenSessionId(handshakeResponse.SessionId)}",
            $"알고리즘: {handshakeResponse.Algorithm}",
            $"만료: {DateTimeOffset.FromUnixTimeMilliseconds(handshakeResponse.ExpiresAtUtc):O}",
            "응답 JSON:",
            PacketDumpFormatter.FormatJson(handshakeResponse));

        promptInput.WaitForEnter("handshake", 3, "login 단계로 진행합니다.");

        var loginPayload = new LoginPayload
        {
            Username = credentials.Username,
            Password = credentials.Password
        };

        reporter.ReportStep(
            "login",
            1,
            "암호화 전 로그인 요청 payload를 준비했습니다.",
            "평문 JSON:",
            PacketDumpFormatter.FormatJson(loginPayload));

        var loginEnvelope = session.EncryptPayload(loginPayload);
        ReportEncryptedPacket(
            reporter,
            "login",
            2,
            "암호화된 로그인 요청 패킷을 전송합니다.",
            loginEnvelope,
            session.SessionSecrets,
            SessionDirection.ClientToServer,
            "송신 packet hex (nonce || ciphertext || tag):");

        var loginResponseEnvelope = await PostJsonAsync<EncryptedEnvelope, EncryptedEnvelope>(
            httpClient,
            "/api/auth/login",
            loginEnvelope,
            cancellationToken);

        ReportEncryptedPacket(
            reporter,
            "login",
            3,
            "암호화된 로그인 응답 패킷을 수신했습니다.",
            loginResponseEnvelope,
            session.SessionSecrets,
            SessionDirection.ServerToClient,
            "수신 packet hex (nonce || ciphertext || tag):");

        var loginResult = session.DecryptPayload<LoginResult>(loginResponseEnvelope);
        reporter.ReportStep(
            "login",
            4,
            "복호화된 로그인 응답 payload를 확인했습니다.",
            $"JWT 만료: {DateTimeOffset.FromUnixTimeMilliseconds(loginResult.ExpiresAtUtc):O}",
            "평문 JSON:",
            PacketDumpFormatter.FormatJson(loginResult));

        promptInput.WaitForEnter("login", 5, "echo 단계로 진행합니다.");

        await RunEchoLoopAsync(httpClient, reporter, promptInput, session, loginResult, cancellationToken);
    }

    /// <summary>
    /// 사용자가 종료를 요청할 때까지 메시지를 입력받아 echo 요청/응답을 반복합니다.
    /// </summary>
    /// <param name="httpClient">echo 요청 전송에 사용할 HTTP 클라이언트입니다.</param>
    /// <param name="reporter">진행상태를 출력할 클라이언트 reporter입니다.</param>
    /// <param name="promptInput">echo 메시지 입력을 수집하는 프롬프트 도우미입니다.</param>
    /// <param name="session">세션 상태와 방향별 암호화 키를 보유한 클라이언트 세션입니다.</param>
    /// <param name="loginResult">보호된 echo 호출에 사용할 JWT 응답 모델입니다.</param>
    /// <param name="cancellationToken">HTTP 호출을 취소할 토큰입니다.</param>
    /// <returns>echo 반복 실행 완료를 나타내는 작업입니다.</returns>
    private static async Task RunEchoLoopAsync(
        HttpClient httpClient,
        ClientProgressReporter reporter,
        ClientPromptInput promptInput,
        ClientSessionState session,
        LoginResult loginResult,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var message = promptInput.PromptForEchoMessage();
            if (message == "quit")
            {
                reporter.ReportStep(
                    "client",
                    2,
                    "quit 입력으로 클라이언트를 종료합니다.",
                    $"세션: {ShortenSessionId(session.SessionId)}");
                return;
            }

            var echoPayload = new EchoPayload
            {
                Message = message
            };

            reporter.ReportStep(
                "echo",
                1,
                "암호화 전 echo 요청 payload를 준비했습니다.",
                "평문 JSON:",
                PacketDumpFormatter.FormatJson(echoPayload));

            var echoEnvelope = session.EncryptPayload(echoPayload);
            ReportEncryptedPacket(
                reporter,
                "echo",
                2,
                "암호화된 echo 요청 패킷을 전송합니다.",
                echoEnvelope,
                session.SessionSecrets,
                SessionDirection.ClientToServer,
                "송신 packet hex (nonce || ciphertext || tag):");

            using var echoRequest = new HttpRequestMessage(HttpMethod.Post, "/api/secure/echo")
            {
                Content = JsonContent.Create(echoEnvelope, options: ProtocolJson.SerializerOptions)
            };
            echoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginResult.AccessToken);

            using var echoResponse = await httpClient.SendAsync(echoRequest, cancellationToken);
            var echoResponseEnvelope = await ReadSuccessJsonAsync<EncryptedEnvelope>(echoResponse, cancellationToken);

            ReportEncryptedPacket(
                reporter,
                "echo",
                3,
                "암호화된 echo 응답 패킷을 수신했습니다.",
                echoResponseEnvelope,
                session.SessionSecrets,
                SessionDirection.ServerToClient,
                "수신 packet hex (nonce || ciphertext || tag):");

            var echoResult = session.DecryptPayload<EchoResult>(echoResponseEnvelope);
            reporter.ReportStep(
                "echo",
                4,
                "복호화된 echo 응답 payload를 확인했습니다.",
                $"서버 시각: {DateTimeOffset.FromUnixTimeMilliseconds(echoResult.ServerTimeUtc):O}",
                "평문 JSON:",
                PacketDumpFormatter.FormatJson(echoResult));
        }
    }

    /// <summary>
    /// JSON payload를 POST로 전송하고 성공 응답 본문을 지정한 형식으로 역직렬화합니다.
    /// </summary>
    /// <typeparam name="TRequest">전송할 요청 본문의 형식입니다.</typeparam>
    /// <typeparam name="TResponse">성공 응답 본문으로 기대하는 형식입니다.</typeparam>
    /// <param name="httpClient">요청 전송에 사용할 HTTP 클라이언트입니다.</param>
    /// <param name="path">BaseAddress 기준 상대 경로입니다.</param>
    /// <param name="payload">JSON으로 직렬화해 전송할 요청 본문입니다.</param>
    /// <param name="cancellationToken">전송과 응답 읽기를 취소할 토큰입니다.</param>
    /// <returns>성공 응답을 역직렬화한 결과를 담은 작업입니다.</returns>
    private static async Task<TResponse> PostJsonAsync<TRequest, TResponse>(
        HttpClient httpClient,
        string path,
        TRequest payload,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.PostAsJsonAsync(path, payload, ProtocolJson.SerializerOptions, cancellationToken);
        return await ReadSuccessJsonAsync<TResponse>(response, cancellationToken);
    }

    /// <summary>
    /// HTTP 응답이 성공 상태인지 확인한 뒤 JSON 본문을 지정한 형식으로 읽어 옵니다.
    /// </summary>
    /// <typeparam name="TResponse">응답 본문으로 기대하는 형식입니다.</typeparam>
    /// <param name="response">검사하고 읽어 올 HTTP 응답입니다.</param>
    /// <param name="cancellationToken">본문 읽기 작업을 취소할 토큰입니다.</param>
    /// <returns>성공 응답에서 역직렬화한 값입니다.</returns>
    private static async Task<TResponse> ReadSuccessJsonAsync<TResponse>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException(
                $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {body}");
        }

        return await response.Content.ReadFromJsonAsync<TResponse>(ProtocolJson.SerializerOptions, cancellationToken)
            ?? throw new InvalidOperationException("The server returned an empty JSON payload.");
    }

    /// <summary>
    /// 암호화 envelope를 CLI에 표시할 hex 블록 형태로 출력합니다.
    /// </summary>
    /// <param name="reporter">진행상태를 출력할 클라이언트 reporter입니다.</param>
    /// <param name="workflow">현재 로그가 속한 workflow 이름입니다.</param>
    /// <param name="step">현재 workflow 안에서의 단계 번호입니다.</param>
    /// <param name="message">사람이 읽는 단계 메시지입니다.</param>
    /// <param name="envelope">hex로 표시할 암호화 envelope입니다.</param>
    /// <param name="sessionSecrets">nonce 계산과 암호문 해석에 사용할 세션 비밀입니다.</param>
    /// <param name="direction">패킷이 이동한 방향입니다.</param>
    /// <param name="packetLabel">hex 블록 앞에 출력할 설명 라벨입니다.</param>
    private static void ReportEncryptedPacket(
        ClientProgressReporter reporter,
        string workflow,
        int step,
        string message,
        EncryptedEnvelope envelope,
        SessionSecrets sessionSecrets,
        SessionDirection direction,
        string packetLabel)
    {
        if (PacketDumpFormatter.TryFormatEncryptedPacketHex(
                envelope,
                sessionSecrets,
                direction,
                out var hexBlock,
                out var errorMessage))
        {
            reporter.ReportStep(
                workflow,
                step,
                message,
                $"세션: {ShortenSessionId(envelope.SessionId)}",
                $"sequence: {envelope.Sequence}",
                $"방향: {DescribeDirection(direction)}",
                packetLabel,
                hexBlock);
            return;
        }

        reporter.ReportStep(
            workflow,
            step,
            message,
            $"세션: {ShortenSessionId(envelope.SessionId)}",
            $"sequence: {envelope.Sequence}",
            $"방향: {DescribeDirection(direction)}",
            $"packet hex 생성 실패: {errorMessage}");
    }

    /// <summary>
    /// 세션 식별자를 콘솔 출력용으로 앞부분만 남겨 축약합니다.
    /// </summary>
    /// <param name="sessionId">축약할 세션 식별자입니다.</param>
    /// <returns>입력이 짧으면 원본, 길면 앞부분만 남긴 식별자입니다.</returns>
    private static string ShortenSessionId(string sessionId) =>
        ShortenText(sessionId, 12);

    /// <summary>
    /// 긴 문자열을 콘솔 출력용으로 앞부분만 남겨 축약합니다.
    /// </summary>
    /// <param name="value">축약해 표시할 원본 문자열입니다.</param>
    /// <param name="maxLength">그대로 보여 줄 최대 길이입니다.</param>
    /// <returns>길이가 짧으면 원본 문자열, 길면 앞부분만 남긴 축약 문자열입니다.</returns>
    private static string ShortenText(string value, int maxLength) =>
        value.Length <= maxLength ? value : $"{value[..maxLength]}...";

    /// <summary>
    /// 세션 방향을 사람이 읽기 쉬운 화살표 형식으로 변환합니다.
    /// </summary>
    /// <param name="direction">표시할 세션 방향입니다.</param>
    /// <returns>예: <c>client -&gt; server</c>, <c>server -&gt; client</c>.</returns>
    private static string DescribeDirection(SessionDirection direction) =>
        direction == SessionDirection.ClientToServer ? "client -> server" : "server -> client";
}
