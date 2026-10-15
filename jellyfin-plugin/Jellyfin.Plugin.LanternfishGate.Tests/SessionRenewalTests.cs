using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Plugin.LanternfishGate.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Jellyfin.Plugin.LanternfishGate.Tests;

public sealed class SessionRenewalTests : IDisposable
{
    private const string Index = "<!DOCTYPE html><html><head><title>Jellyfin</title></head><body>app</body></html>";

    private readonly ECDsa _gateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ConcurrentQueue<string> _seenAcceptEncoding = new();

    public void Dispose() => _gateKey.Dispose();

    private async Task<(HttpClient Client, IHost Host)> Start(bool inject)
    {
        var policy = GatePolicy.From(new PluginConfiguration
        {
            GatePublicKeys = Convert.ToBase64String(_gateKey.ExportSubjectPublicKeyInfo()),
            InjectSessionRenewal = inject,
        });
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddSingleton<Func<GatePolicy?>>(() => policy))
                .Configure(app =>
                {
                    app.UseMiddleware<GateSignatureMiddleware>();
                    app.Run(async ctx =>
                    {
                        // Stands in for Jellyfin's static web client.
                        _seenAcceptEncoding.Enqueue(ctx.Request.Headers.AcceptEncoding.ToString());
                        ctx.Response.ContentType = "text/html; charset=utf-8";
                        ctx.Response.Headers.ETag = "\"abc\"";
                        await ctx.Response.WriteAsync(Index);
                    });
                }))
            .StartAsync();
        return (host.GetTestClient(), host);
    }

    // Builds a request the way the Gate would sign it.
    private HttpRequestMessage Signed(string target, string auth)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N");
        var sig = _gateKey.SignData(
            GateSignatureVerifier.Message("GET", target, ts, nonce, "dev_test"),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var req = new HttpRequestMessage(HttpMethod.Get, target);
        req.Headers.Add(GateSignatureMiddleware.TimestampHeader, ts);
        req.Headers.Add(GateSignatureMiddleware.NonceHeader, nonce);
        req.Headers.Add(GateSignatureMiddleware.DeviceHeader, "dev_test");
        req.Headers.Add(GateSignatureMiddleware.SignatureHeader, Convert.ToBase64String(sig));
        req.Headers.Add(SessionRenewal.AuthHeader, auth);
        req.Headers.Add("Accept-Encoding", "gzip");
        return req;
    }

    [Theory]
    [InlineData("/web/")]
    [InlineData("/web/index.html")]
    [InlineData("/jellyfin/web/index.html")]
    public async Task AddsScriptForBrowserSessions(string path)
    {
        var (client, host) = await Start(inject: true);
        using (host)
        {
            var resp = await client.SendAsync(Signed(path, "cookie"));
            var body = await resp.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal(1, CountOf(body, SessionRenewal.Script));
            Assert.Contains(SessionRenewal.Script + "</head>", body, StringComparison.Ordinal);
            Assert.True(resp.Headers.Contains(SessionRenewal.MarkerHeader));
            Assert.Null(resp.Headers.ETag);
            Assert.Equal(body.Length, (int)resp.Content.Headers.ContentLength!);
            Assert.True(_seenAcceptEncoding.TryDequeue(out var enc) && enc.Length == 0, "Accept-Encoding should be removed");
        }
    }

    [Theory]
    [InlineData(true, "header", "/web/index.html")]     // app with session header
    [InlineData(true, "certificate", "/web/index.html")] // app with client certificate
    [InlineData(true, "cookie", "/web/ConfigurationPage")] // not the index
    [InlineData(false, "cookie", "/web/index.html")]    // setting off: the Gate adds it instead
    public async Task LeavesPageAloneOtherwise(bool inject, string auth, string path)
    {
        var (client, host) = await Start(inject);
        using (host)
        {
            var resp = await client.SendAsync(Signed(path, auth));
            var body = await resp.Content.ReadAsStringAsync();
            Assert.Equal(Index, body);
            Assert.False(resp.Headers.Contains(SessionRenewal.MarkerHeader));
        }
    }

    private static int CountOf(string haystack, string needle)
    {
        var n = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + 1, StringComparison.Ordinal))
        {
            n++;
        }

        return n;
    }
}
