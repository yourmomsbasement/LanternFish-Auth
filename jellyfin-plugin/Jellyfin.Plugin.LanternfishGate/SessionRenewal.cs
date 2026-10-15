using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
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

        var original = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;
        try
        {
            await next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Response.Body = original;
        }

        var response = context.Response;
        var bytes = buffer.ToArray();
        if (response.StatusCode == StatusCodes.Status200OK
            && (response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) ?? false)
            && string.IsNullOrEmpty(response.Headers.ContentEncoding)
            && bytes.Length <= MaxIndexSize)
        {
            var html = Encoding.UTF8.GetString(bytes);
            var head = html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
            if (head >= 0 && !html.Contains("/_lanternfish/gate-client.js", StringComparison.Ordinal))
            {
                bytes = Encoding.UTF8.GetBytes(html.Insert(head, Script));
                response.Headers.Remove(HeaderNames.ETag);
                response.Headers.Remove(HeaderNames.LastModified);
            }

            response.Headers[MarkerHeader] = "injected";
        }

        response.ContentLength = bytes.Length;
        await original.WriteAsync(bytes).ConfigureAwait(false);
    }
}
