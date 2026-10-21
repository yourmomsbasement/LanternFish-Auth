using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>
/// Refuses every request that does not carry a valid Lanternfish Gate signature.
/// Runs ahead of all of Jellyfin's own middleware.
/// </summary>
public sealed class GateSignatureMiddleware
{
    /// <summary>Header carrying the Gate's timestamp.</summary>
    public const string TimestampHeader = "X-Lanternfish-Gate-Timestamp";

    /// <summary>Header carrying the Gate's nonce.</summary>
    public const string NonceHeader = "X-Lanternfish-Gate-Nonce";

    /// <summary>Header carrying the Gate's signature.</summary>
    public const string SignatureHeader = "X-Lanternfish-Gate-Signature";

    /// <summary>Header carrying the authenticated device ID.</summary>
    public const string DeviceHeader = "X-Lanternfish-Device";

    private static readonly TimeSpan _logInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan _unconfiguredInterval = TimeSpan.FromMinutes(10);

    private readonly RequestDelegate _next;
    private readonly Func<GatePolicy?> _policy;
    private readonly ILogger<GateSignatureMiddleware> _logger;
    private readonly Func<DateTimeOffset> _clock;
    private long _rejected;
    private long _nextLog;
    private long _nextUnconfiguredWarning;

    /// <summary>Initializes a new instance of the <see cref="GateSignatureMiddleware"/> class.</summary>
    /// <param name="next">The next middleware.</param>
    /// <param name="policy">Supplies the current policy; null while the plugin is still loading.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="clock">The clock, overridable for tests.</param>
    public GateSignatureMiddleware(RequestDelegate next, Func<GatePolicy?> policy, ILogger<GateSignatureMiddleware> logger, Func<DateTimeOffset>? clock = null)
    {
        _next = next;
        _policy = policy;
        _logger = logger;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Handles one request.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>A task.</returns>
    public Task InvokeAsync(HttpContext context)
    {
        var policy = _policy();
        if (policy is null)
        {
            return Reject(context, StatusCodes.Status503ServiceUnavailable, "starting");
        }

        if (policy.ConfigError is not null)
        {
            // Fail closed: a broken key must not open the server.
            Log(LogLevel.Error, "Lanternfish Gate plugin is misconfigured ({Error}); refusing all requests.", policy.ConfigError);
            return Reject(context, StatusCodes.Status503ServiceUnavailable, "misconfigured");
        }

        if (policy.Verifier is null)
        {
            // Repeated (every ten minutes) rather than once, so it isn't lost
            // in a long-running server's log.
            var nowMs = _clock().ToUnixTimeMilliseconds();
            var due = Interlocked.Read(ref _nextUnconfiguredWarning);
            if (nowMs >= due && Interlocked.CompareExchange(ref _nextUnconfiguredWarning, nowMs + (long)_unconfiguredInterval.TotalMilliseconds, due) == due)
            {
                _logger.LogWarning("Lanternfish Gate plugin has no Gate key configured, so it is NOT enforcing anything yet. Paste the output of `lanternfish-gate upstream-key` into the plugin settings.");
            }

            return _next(context);
        }

        var request = context.Request;
        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target))
        {
            target = request.PathBase + request.Path + request.QueryString;
        }

        if (policy.AllowLoopbackHealthCheck && IsLoopbackHealthCheck(context, target))
        {
            return _next(context);
        }

        var result = policy.Verifier.Verify(
            request.Method,
            target,
            Single(request.Headers[TimestampHeader]),
            Single(request.Headers[NonceHeader]),
            Single(request.Headers[DeviceHeader]),
            Single(request.Headers[SignatureHeader]),
            _clock());
        if (result != VerifyResult.Ok)
        {
            var count = Interlocked.Increment(ref _rejected);
            // SECURITY (L5): log the raw target, which is still
            // percent-encoded (so it holds no line breaks), quoted and cut
            // short, never the decoded path.
            Log(
                LogLevel.Warning,
                "Lanternfish Gate plugin rejected {Method} {Target} from {Remote}: {Result} ({Count} rejected so far).",
                Printable(request.Method, 16),
                Printable(target, 200),
                context.Connection.RemoteIpAddress,
                result,
                count);
            return result switch
            {
                VerifyResult.Overloaded => Reject(context, StatusCodes.Status503ServiceUnavailable, "too many requests; try again shortly"),
                VerifyResult.DeviceOverloaded => Reject(context, StatusCodes.Status429TooManyRequests, "too many requests from this device; try again shortly"),
                _ => Reject(context, StatusCodes.Status403Forbidden, "requests must come through Lanternfish Gate"),
            };
        }

        if (policy.InjectSessionRenewal && SessionRenewal.Applies(request))
        {
            return SessionRenewal.InjectAsync(context, _next);
        }

        return _next(context);
    }

    private static string? Single(Microsoft.Extensions.Primitives.StringValues values) => values.Count == 1 ? values[0] : null;

    private static bool IsLoopbackHealthCheck(HttpContext context, string target)
    {
        var request = context.Request;
        var remote = context.Connection.RemoteIpAddress;
        var headers = request.Headers;
        return (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
            && remote is not null
            && IPAddress.IsLoopback(remote)
            // SECURITY (L8): the loopback address is only trustworthy while
            // nothing has rewritten it from forwarding headers. If forwarded
            // headers are present (or a forwarded-headers middleware ran
            // first and left X-Original-For), don't exempt anything.
            && !headers.ContainsKey("X-Forwarded-For")
            && !headers.ContainsKey("X-Original-For")
            && !headers.ContainsKey("Forwarded")
            // SECURITY: exactly /health as sent, not any path ending in it
            // (/Foo/health) nor one that only decodes to it (/he%61lth).
            && string.Equals(target, "/health", StringComparison.OrdinalIgnoreCase);
    }

    private static string Printable(string value, int max)
    {
        var sb = new System.Text.StringBuilder(Math.Min(value.Length, max) + 2);
        sb.Append('"');
        foreach (var c in value.Length > max ? value[..max] : value)
        {
            sb.Append(char.IsControl(c) || c == '"' ? '?' : c);
        }

        sb.Append(value.Length > max ? "\"…" : "\"");
        return sb.ToString();
    }

    private static Task Reject(HttpContext context, int status, string reason)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync("Forbidden: " + reason + ".\n");
    }

    // Rate-limits logging so a scan can't flood the log.
    private void Log(LogLevel level, string message, params object?[] args)
    {
        var now = _clock().ToUnixTimeMilliseconds();
        var due = Interlocked.Read(ref _nextLog);
        if (now < due || Interlocked.CompareExchange(ref _nextLog, now + (long)_logInterval.TotalMilliseconds, due) != due)
        {
            return;
        }

#pragma warning disable CA2254 // Template is a constant at every call site.
        _logger.Log(level, message, args);
#pragma warning restore CA2254
    }
}
