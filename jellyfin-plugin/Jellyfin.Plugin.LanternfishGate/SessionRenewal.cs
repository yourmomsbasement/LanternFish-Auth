using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>
/// Adds the Gate's session-renewal script to the web client's index.html, so
/// a browser's 15-minute Gate session is renewed in the background instead of
/// expiring under the running app. The response is marked so the Gate doesn't
/// add the script a second time.
/// </summary>
public static class SessionRenewal
{
    /// <summary>How the Gate says the request authenticated.</summary>
    public const string AuthHeader = "X-Lanternfish-Auth";

    /// <summary>Marks a response the plugin has already added the script to.</summary>
    public const string MarkerHeader = "X-Lanternfish-Renewal";

    /// <summary>The script tag that is added.</summary>
    public const string Script = "<script src=\"/_lanternfish/gate-client.js\" data-autorenew></script>";

    private const int MaxIndexSize = 4 << 20;

    private static readonly Regex _webIndex = new("(^|/)web/(index\\.html)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// Whether a (Gate-verified) request is a browser loading the web client.
    /// Apps using client certificates or the session header never get the
    /// script: it would send them to the browser sign-in page.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>True to add the script.</returns>
    public static bool Applies(HttpRequest request) =>
        HttpMethods.IsGet(request.Method)
        && string.Equals(request.Headers[AuthHeader].ToString(), "cookie", StringComparison.Ordinal)
        && _webIndex.IsMatch((request.PathBase + request.Path).Value ?? string.Empty);

    /// <summary>Runs the rest of the pipeline and adds the script to its HTML.</summary>
    /// <param name="context">The request context.</param>
    /// <param name="next">The rest of the pipeline.</param>
    /// <returns>A task.</returns>
    public static async Task InjectAsync(HttpContext context, RequestDelegate next)
    {
        // Ask for the full, uncompressed page.
        var headers = context.Request.Headers;
        headers.Remove(HeaderNames.AcceptEncoding);
        headers.Remove(HeaderNames.IfNoneMatch);
        headers.Remove(HeaderNames.IfModifiedSince);

        // SECURITY: buffer at most MaxIndexSize. A bigger response is passed
        // through untouched as it is written, instead of being held in memory
        // in full and only then found too big to change.
        var original = context.Response.Body;
        await using var capture = new BoundedCaptureStream(original, MaxIndexSize);
        context.Response.Body = capture;
        try
        {
            await next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Response.Body = original;
        }

        if (!capture.TryGetCaptured(out var captured))
        {
            return; // already passed through
        }

        var response = context.Response;
        if (response.StatusCode == StatusCodes.Status200OK
            && (response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) ?? false)
            && string.IsNullOrEmpty(response.Headers.ContentEncoding))
        {
            var html = Encoding.UTF8.GetString(captured.Span);
            var head = html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
            if (head >= 0 && !html.Contains("/_lanternfish/gate-client.js", StringComparison.Ordinal))
            {
                captured = Encoding.UTF8.GetBytes(html.Insert(head, Script));
                response.Headers.Remove(HeaderNames.ETag);
                response.Headers.Remove(HeaderNames.LastModified);
            }

            response.Headers[MarkerHeader] = "injected";
        }

        response.ContentLength = captured.Length;
        await original.WriteAsync(captured).ConfigureAwait(false);
    }

    /// <summary>
    /// Holds a response body in memory up to a limit. Past the limit it writes
    /// what it holds to the real body and passes the rest straight through.
    /// </summary>
    private sealed class BoundedCaptureStream : Stream
    {
        private readonly Stream _inner;
        private readonly int _limit;
        private MemoryStream? _buffer = new();

        public BoundedCaptureStream(Stream inner, int limit)
        {
            _inner = inner;
            _limit = limit;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <summary>Gets the whole body, if it stayed within the limit.</summary>
        public bool TryGetCaptured(out ReadOnlyMemory<byte> body)
        {
            if (_buffer is null)
            {
                body = default;
                return false;
            }

            body = _buffer.GetBuffer().AsMemory(0, (int)_buffer.Length);
            return true;
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (_buffer is not null && _buffer.Length + buffer.Length <= _limit)
            {
                _buffer.Write(buffer);
                return;
            }

            if (_buffer is not null)
            {
                _buffer.Position = 0;
                _buffer.CopyTo(_inner);
                _buffer = null;
            }

            _inner.Write(buffer);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_buffer is not null && _buffer.Length + buffer.Length <= _limit)
            {
                _buffer.Write(buffer.Span);
                return;
            }

            if (_buffer is not null)
            {
                var held = _buffer;
                _buffer = null;
                await _inner.WriteAsync(held.GetBuffer().AsMemory(0, (int)held.Length), cancellationToken).ConfigureAwait(false);
            }

            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        // Flushing while capturing would start the response before it can be changed.
        public override void Flush()
        {
            if (_buffer is null)
            {
                _inner.Flush();
            }
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            _buffer is null ? _inner.FlushAsync(cancellationToken) : Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
