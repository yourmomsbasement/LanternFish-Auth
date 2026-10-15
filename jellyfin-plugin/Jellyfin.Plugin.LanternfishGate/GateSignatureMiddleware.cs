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

    private readonly RequestDelegate _next;
    private readonly Func<GatePolicy?> _policy;
    private readonly ILogger<GateSignatureMiddleware> _logger;
    private readonly Func<DateTimeOffset> _clock;
    private long _rejected;
    private long _nextLog;
    private int _warnedUnconfigured;

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
            if (Interlocked.Exchange(ref _warnedUnconfigured, 1) == 0)
            {
                _logger.LogWarning("Lanternfish Gate plugin has no Gate key configured, so it is NOT enforcing anything yet. Paste the output of `lanternfish-gate upstream-key` into the plugin settings.");
            }

            return _next(context);
        }

        var request = context.Request;
        if (policy.AllowLoopbackHealthCheck && IsLoopbackHealthCheck(context))
        {
            return _next(context);
        }

        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target))
        {
            target = request.PathBase + request.Path + request.QueryString;
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
            Log(
                LogLevel.Warning,
                "Lanternfish Gate plugin rejected {Method} {Path} from {Remote}: {Result} ({Count} rejected so far).",
                request.Method,
                request.Path.Value,
                context.Connection.RemoteIpAddress,
                result,
                count);
            return Reject(context, StatusCodes.Status403Forbidden, "requests must come through Lanternfish Gate");
        }

        if (policy.InjectSessionRenewal && SessionRenewal.Applies(request))
        {
            return SessionRenewal.InjectAsync(context, _next);
        }

        return _next(context);
    }

    private static string? Single(Microsoft.Extensions.Primitives.StringValues values) => values.Count == 1 ? values[0] : null;

    private static bool IsLoopbackHealthCheck(HttpContext context)
    {
        var request = context.Request;
        var remote = context.Connection.RemoteIpAddress;
        return (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
            && remote is not null
            && IPAddress.IsLoopback(remote)
            // SECURITY: exactly /health, not any path ending in it, so the
            // exemption can't reach another endpoint (e.g. /Foo/health).
            && string.Equals(request.Path.Value, "/health", StringComparison.OrdinalIgnoreCase);
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
