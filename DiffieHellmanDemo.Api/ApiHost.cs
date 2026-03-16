using System.Security.Claims;
using DiffieHellmanDemo.Api.Services;
using DiffieHellmanDemo.Common.Contracts;
using DiffieHellmanDemo.Common.Crypto;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace DiffieHellmanDemo.Api;

/// <summary>
/// 데모 API 서버의 서비스 등록과 HTTP 파이프라인 구성을 담당합니다.
/// </summary>
public static class ApiHost
{
    private static readonly string[] DemoEndpoints =
    [
        "POST /api/session/handshake",
        "POST /api/auth/login",
        "POST /api/secure/echo"
    ];

    /// <summary>
    /// 데모 API에 필요한 DI 서비스, 인증, 엔드포인트를 모두 구성한 <see cref="WebApplication"/>을 생성합니다.
    /// </summary>
    /// <param name="args">호스트 구성에 전달할 명령줄 인자입니다.</param>
    /// <returns>실행 직전 상태로 구성된 ASP.NET Core 웹 애플리케이션입니다.</returns>
    public static WebApplication BuildApp(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var jwtSigningOptions = new JwtSigningOptions();
        var progressReporter = new ServerProgressReporter(!builder.Environment.IsEnvironment("Testing"));

        progressReporter.ReportStep(
            "server",
            1,
            "서버 부팅을 시작합니다.",
            $"환경: {builder.Environment.EnvironmentName}");

        progressReporter.ReportStep(
            "server",
            2,
            "인증, 암호화, 세션 서비스를 등록합니다.");
        builder.Services.AddProblemDetails();
        builder.Services.AddOpenApi();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(jwtSigningOptions);
        builder.Services.AddSingleton(progressReporter);
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = jwtSigningOptions.CreateValidationParameters();
                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        if (context.Request.Path.StartsWithSegments("/api/secure/echo"))
                        {
                            progressReporter.ReportStep(
                                "echo",
                                2,
                                "JWT 인증에 실패했습니다.",
                                $"HTTP 상태: {StatusCodes.Status401Unauthorized}",
                                $"경로: {context.Request.Path}",
                                $"사유: {ShortenText(context.AuthenticateFailure?.Message, 48)}");
                        }

                        return Task.CompletedTask;
                    }
                };
            });
        builder.Services.AddSingleton<SessionStore>();
        builder.Services.AddSingleton<SessionHandshakeService>();
        builder.Services.AddSingleton<SessionCryptoService>();
        builder.Services.AddSingleton<DemoUserService>();
        builder.Services.AddSingleton<JwtTokenService>();

        progressReporter.ReportStep(
            "server",
            3,
            "웹 애플리케이션을 빌드합니다.");
        var app = builder.Build();

        progressReporter.ReportStep(
            "server",
            4,
            "미들웨어 파이프라인을 구성합니다.",
            $"HTTPS 리디렉션: {!app.Environment.IsEnvironment("Testing")}",
            $"OpenAPI 노출: {app.Environment.IsDevelopment()}");
        app.UseExceptionHandler();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
        }

        if (!app.Environment.IsEnvironment("Testing"))
        {
            app.UseHttpsRedirection();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/", () => Results.Ok(new
        {
            name = "DiffieHellmanDemo.Api",
            endpoints = DemoEndpoints
        }));

        progressReporter.ReportStep(
            "server",
            5,
            "프로토콜 엔드포인트를 매핑합니다.",
            $"엔드포인트: {string.Join(", ", DemoEndpoints)}");
        var api = app.MapGroup("/api");

        api.MapGroup("/session")
            .MapPost("/handshake", (
                HandshakeRequest request,
                SessionHandshakeService handshakeService,
                ServerProgressReporter reporter) =>
            {
                reporter.ReportStep(
                    "handshake",
                    1,
                    "핸드셰이크 요청을 수신했습니다.",
                    "요청 JSON:",
                    PacketDumpFormatter.FormatJson(request));

                try
                {
                    var response = handshakeService.CreateHandshake(request);

                    reporter.ReportStep(
                        "handshake",
                        2,
                        "핸드셰이크 응답을 전송합니다.",
                        $"세션: {ShortenSessionId(response.SessionId)}",
                        $"만료: {DateTimeOffset.FromUnixTimeMilliseconds(response.ExpiresAtUtc):O}",
                        $"알고리즘: {response.Algorithm}",
                        "응답 JSON:",
                        PacketDumpFormatter.FormatJson(response));

                    return Results.Ok(response);
                }
                catch (ProtocolFailureException ex)
                {
                    reporter.ReportStep(
                        "handshake",
                        2,
                        "핸드셰이크 처리에 실패했습니다.",
                        $"HTTP 상태: {ex.StatusCode}",
                        $"사유: {ex.Title}");
                    return CreateProblem(ex);
                }
            })
            .AllowAnonymous()
            .WithName("CreateHandshake");

        api.MapGroup("/auth")
            .MapPost("/login", (
                EncryptedEnvelope envelope,
                SessionStore sessionStore,
                SessionCryptoService sessionCryptoService,
                DemoUserService demoUserService,
                JwtTokenService jwtTokenService,
                ServerProgressReporter reporter) =>
            {
                reporter.ReportStep(
                    "login",
                    1,
                    "암호화 로그인 요청을 수신했습니다.",
                    $"세션: {ShortenSessionId(envelope.SessionId)}",
                    $"요청 sequence: {envelope.Sequence}");

                try
                {
                    var session = sessionStore.GetRequired(envelope.SessionId);
                    ReportEncryptedPacket(
                        reporter,
                        "login",
                        2,
                        "수신 암호화 로그인 패킷을 확인했습니다.",
                        envelope,
                        session.SessionSecrets,
                        SessionDirection.ClientToServer,
                        "수신 packet hex (nonce || ciphertext || tag):");

                    var payload = sessionCryptoService.DecryptClientEnvelope<LoginPayload>(session, envelope);
                    reporter.ReportStep(
                        "login",
                        3,
                        "복호화된 로그인 요청 payload를 확인했습니다.",
                        "평문 JSON:",
                        PacketDumpFormatter.FormatJson(payload));

                    if (!demoUserService.TryValidateCredentials(payload.Username, payload.Password, out var user))
                    {
                        reporter.ReportStep(
                            "login",
                            4,
                            "계정 검증에 실패했습니다.",
                            $"HTTP 상태: {StatusCodes.Status401Unauthorized}",
                            $"세션: {ShortenSessionId(session.SessionId)}",
                            $"사용자: {payload.Username}");
                        return Results.Problem(
                            statusCode: StatusCodes.Status401Unauthorized,
                            title: "Invalid credentials",
                            detail: "The supplied username or password is incorrect.");
                    }

                    var loginResult = jwtTokenService.CreateLoginResult(user.UserName, session.SessionId, session.ExpiresAtUtc);
                    reporter.ReportStep(
                        "login",
                        4,
                        "암호화 전 로그인 응답 payload를 생성했습니다.",
                        "평문 JSON:",
                        PacketDumpFormatter.FormatJson(loginResult));

                    var responseEnvelope = sessionCryptoService.EncryptServerEnvelope(session, loginResult);
                    ReportEncryptedPacket(
                        reporter,
                        "login",
                        5,
                        "암호화된 로그인 응답 패킷을 전송합니다.",
                        responseEnvelope,
                        session.SessionSecrets,
                        SessionDirection.ServerToClient,
                        "송신 packet hex (nonce || ciphertext || tag):");

                    return Results.Ok(responseEnvelope);
                }
                catch (ProtocolFailureException ex)
                {
                    reporter.ReportStep(
                        "login",
                        2,
                        "로그인 처리에 실패했습니다.",
                        $"HTTP 상태: {ex.StatusCode}",
                        $"사유: {ex.Title}",
                        $"세션: {ShortenSessionId(envelope.SessionId)}");
                    return CreateProblem(ex);
                }
            })
            .AllowAnonymous()
            .WithName("EncryptedLogin");

        api.MapGroup("/secure")
            .RequireAuthorization()
            .MapPost("/echo", (
                ClaimsPrincipal principal,
                EncryptedEnvelope envelope,
                SessionStore sessionStore,
                SessionCryptoService sessionCryptoService,
                TimeProvider timeProvider,
                ServerProgressReporter reporter) =>
            {
                reporter.ReportStep(
                    "echo",
                    1,
                    "보호된 echo 요청을 수신했습니다.",
                    $"세션: {ShortenSessionId(envelope.SessionId)}",
                    $"요청 sequence: {envelope.Sequence}");

                SessionState session;

                try
                {
                    session = sessionStore.GetRequired(envelope.SessionId);
                    ReportEncryptedPacket(
                        reporter,
                        "echo",
                        2,
                        "수신 암호화 echo 패킷을 확인했습니다.",
                        envelope,
                        session.SessionSecrets,
                        SessionDirection.ClientToServer,
                        "수신 packet hex (nonce || ciphertext || tag):");
                }
                catch (ProtocolFailureException ex)
                {
                    reporter.ReportStep(
                        "echo",
                        2,
                        "echo 처리에 실패했습니다.",
                        $"HTTP 상태: {ex.StatusCode}",
                        $"사유: {ex.Title}",
                        $"세션: {ShortenSessionId(envelope.SessionId)}");
                    return CreateProblem(ex);
                }

                var sessionClaim = principal.FindFirst("sid")?.Value;
                if (!string.Equals(sessionClaim, envelope.SessionId, StringComparison.Ordinal))
                {
                    reporter.ReportStep(
                        "echo",
                        3,
                        "JWT와 세션 검증에 실패했습니다.",
                        $"HTTP 상태: {StatusCodes.Status403Forbidden}",
                        $"JWT sid: {ShortenSessionId(sessionClaim)}",
                        $"Envelope session: {ShortenSessionId(envelope.SessionId)}");
                    return Results.Problem(
                        statusCode: StatusCodes.Status403Forbidden,
                        title: "Session mismatch",
                        detail: "The JWT sid claim does not match the encrypted session.");
                }

                try
                {
                    var payload = sessionCryptoService.DecryptClientEnvelope<EchoPayload>(session, envelope);
                    var userName = principal.Identity?.Name ?? principal.FindFirst(ClaimTypes.Name)?.Value ?? "unknown";

                    reporter.ReportStep(
                        "echo",
                        3,
                        "복호화된 echo 요청 payload를 확인했습니다.",
                        "평문 JSON:",
                        PacketDumpFormatter.FormatJson(payload));

                    var response = new EchoResult
                    {
                        EchoedMessage = payload.Message,
                        UserName = userName,
                        ServerTimeUtc = timeProvider.GetUtcNow().ToUnixTimeMilliseconds()
                    };

                    reporter.ReportStep(
                        "echo",
                        4,
                        "암호화 전 echo 응답 payload를 생성했습니다.",
                        "평문 JSON:",
                        PacketDumpFormatter.FormatJson(response));

                    var responseEnvelope = sessionCryptoService.EncryptServerEnvelope(session, response);
                    ReportEncryptedPacket(
                        reporter,
                        "echo",
                        5,
                        "암호화된 echo 응답 패킷을 전송합니다.",
                        responseEnvelope,
                        session.SessionSecrets,
                        SessionDirection.ServerToClient,
                        "송신 packet hex (nonce || ciphertext || tag):");

                    return Results.Ok(responseEnvelope);
                }
                catch (ProtocolFailureException ex)
                {
                    reporter.ReportStep(
                        "echo",
                        3,
                        "echo 처리에 실패했습니다.",
                        $"HTTP 상태: {ex.StatusCode}",
                        $"사유: {ex.Title}",
                        $"세션: {ShortenSessionId(envelope.SessionId)}");
                    return CreateProblem(ex);
                }
            })
            .WithName("EncryptedEcho");

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            progressReporter.ReportStep(
                "server",
                6,
                "서버 준비가 완료되었습니다.",
                $"환경: {app.Environment.EnvironmentName}",
                $"활성 URL: {DescribeUrls(app.Urls)}",
                $"엔드포인트: {string.Join(", ", DemoEndpoints)}");
        });

        return app;
    }

    /// <summary>
    /// 프로토콜 처리 중 발생한 예외를 표준 ProblemDetails 응답으로 변환합니다.
    /// </summary>
    /// <param name="ex">HTTP 상태 코드와 사용자 노출 메시지를 포함한 프로토콜 예외입니다.</param>
    /// <returns>클라이언트에 반환할 ProblemDetails 기반 실패 결과입니다.</returns>
    private static IResult CreateProblem(ProtocolFailureException ex) =>
        Results.Problem(statusCode: ex.StatusCode, title: ex.Title, detail: ex.Message);

    /// <summary>
    /// 암호화 envelope를 CLI에 표시할 hex 블록 형태로 출력합니다.
    /// </summary>
    /// <param name="reporter">진행상태를 출력할 서버 reporter입니다.</param>
    /// <param name="workflow">현재 로그가 속한 workflow 이름입니다.</param>
    /// <param name="step">현재 workflow 안에서의 단계 번호입니다.</param>
    /// <param name="message">사람이 읽는 단계 메시지입니다.</param>
    /// <param name="envelope">hex로 표시할 암호화 envelope입니다.</param>
    /// <param name="sessionSecrets">nonce 계산과 암호문 해석에 사용할 세션 비밀입니다.</param>
    /// <param name="direction">패킷이 이동한 방향입니다.</param>
    /// <param name="packetLabel">hex 블록 앞에 출력할 설명 라벨입니다.</param>
    private static void ReportEncryptedPacket(
        ServerProgressReporter reporter,
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
    /// 콘솔 출력에 표시할 세션 식별자를 짧게 축약합니다.
    /// </summary>
    /// <param name="sessionId">축약해 보여 줄 세션 식별자입니다.</param>
    /// <returns>입력이 비어 있으면 대체 문자열, 길면 앞부분만 남긴 식별자입니다.</returns>
    private static string ShortenSessionId(string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return "(없음)";
        }

        return sessionId.Length <= 12 ? sessionId : $"{sessionId[..12]}...";
    }

    /// <summary>
    /// 자유 텍스트를 콘솔 출력용으로 최대 길이만큼 잘라 표시합니다.
    /// </summary>
    /// <param name="value">축약해서 보여 줄 텍스트입니다.</param>
    /// <param name="maxLength">그대로 보여 줄 최대 길이입니다.</param>
    /// <returns>입력이 비어 있으면 대체 문자열, 길면 앞부분만 남긴 문자열입니다.</returns>
    private static string ShortenText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "(없음)";
        }

        return value.Length <= maxLength ? value : $"{value[..maxLength]}...";
    }

    /// <summary>
    /// 현재 서버가 바인딩한 URL 목록을 사람이 읽기 쉬운 문자열로 결합합니다.
    /// </summary>
    /// <param name="urls">애플리케이션이 노출 중인 URL 목록입니다.</param>
    /// <returns>활성 URL이 있으면 쉼표로 연결한 문자열, 없으면 대체 문자열입니다.</returns>
    private static string DescribeUrls(IEnumerable<string> urls)
    {
        var activeUrls = urls.Where(url => !string.IsNullOrWhiteSpace(url)).OrderBy(url => url).ToArray();
        return activeUrls.Length == 0 ? "(호스트 기본값)" : string.Join(", ", activeUrls);
    }

    /// <summary>
    /// 세션 방향을 사람이 읽기 쉬운 화살표 형식으로 변환합니다.
    /// </summary>
    /// <param name="direction">표시할 세션 방향입니다.</param>
    /// <returns>예: <c>client -&gt; server</c>, <c>server -&gt; client</c>.</returns>
    private static string DescribeDirection(SessionDirection direction) =>
        direction == SessionDirection.ClientToServer ? "client -> server" : "server -> client";
}
