using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
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

public class GateTests
{
    private sealed record Vector(string public_key, string method, string target, long timestamp, string nonce, string device_id, string signature);

    private static Vector LoadVector() =>
        JsonSerializer.Deserialize<Vector>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "upstream-vector.json")))!;

    private static GateSignatureVerifier VerifierFor(string key) => new([key], TimeSpan.FromSeconds(30));

    [Fact]
    public void AcceptsSignatureMadeByTheGate()
    {
        var v = LoadVector();
        using var verifier = VerifierFor(v.public_key);
        var at = DateTimeOffset.FromUnixTimeSeconds(v.timestamp + 5);
        Assert.Equal(VerifyResult.Ok, verifier.Verify(v.method, v.target, v.timestamp.ToString(), v.nonce, v.device_id, v.signature, at));
        Assert.Equal(VerifyResult.Replayed, verifier.Verify(v.method, v.target, v.timestamp.ToString(), v.nonce, v.device_id, v.signature, at));
    }

    [Fact]
    public void RejectsTamperingStalenessAndOtherKeys()
    {
        var v = LoadVector();
        using var verifier = VerifierFor(v.public_key);
        var ts = v.timestamp.ToString();
        var at = DateTimeOffset.FromUnixTimeSeconds(v.timestamp);

        Assert.Equal(VerifyResult.BadSignature, verifier.Verify("POST", v.target, ts, v.nonce, v.device_id, v.signature, at));
        Assert.Equal(VerifyResult.BadSignature, verifier.Verify(v.method, "/Users", ts, v.nonce, v.device_id, v.signature, at));
        Assert.Equal(VerifyResult.BadSignature, verifier.Verify(v.method, v.target, ts, v.nonce, "dev_other", v.signature, at));
        Assert.Equal(VerifyResult.Stale, verifier.Verify(v.method, v.target, ts, v.nonce, v.device_id, v.signature, at.AddSeconds(31)));
        Assert.Equal(VerifyResult.Stale, verifier.Verify(v.method, v.target, ts, v.nonce, v.device_id, v.signature, at.AddSeconds(-31)));
        Assert.Equal(VerifyResult.Missing, verifier.Verify(v.method, v.target, null, v.nonce, v.device_id, v.signature, at));
        Assert.Equal(VerifyResult.Malformed, verifier.Verify(v.method, v.target, "-5", v.nonce, v.device_id, v.signature, at));
        Assert.Equal(VerifyResult.Malformed, verifier.Verify(v.method, v.target, ts, v.nonce, v.device_id, "!!", at));

        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = VerifierFor(Convert.ToBase64String(other.ExportSubjectPublicKeyInfo()));
        Assert.Equal(VerifyResult.BadSignature, wrongKey.Verify(v.method, v.target, ts, v.nonce, v.device_id, v.signature, at));

        // A failed attempt must not burn the nonce for the genuine request.
        Assert.Equal(VerifyResult.Ok, verifier.Verify(v.method, v.target, ts, v.nonce, v.device_id, v.signature, at));
    }

    [Fact]
    public void RejectsNonP256Keys()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<FormatException>(() => GateSignatureVerifier.ParseKey(Convert.ToBase64String(p384.ExportSubjectPublicKeyInfo())));
        Assert.Throws<FormatException>(() => GateSignatureVerifier.ParseKey("not base64"));
        var policy = GatePolicy.From(new PluginConfiguration { GatePublicKeys = "AAAA" });
        Assert.NotNull(policy.ConfigError);
    }

    // ---- Middleware, in a real ASP.NET Core pipeline ----

    private static async Task<(HttpClient Client, IHost Host)> Start(GatePolicy? policy, DateTimeOffset now)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s => s.AddSingleton<Func<GatePolicy?>>(() => policy).AddSingleton<Func<DateTimeOffset>>(() => now))
                .Configure(app =>
                {
                    app.UseMiddleware<GateSignatureMiddleware>();
                    app.Run(ctx => ctx.Response.WriteAsync("jellyfin"));
                }))
            .StartAsync();
        return (host.GetTestClient(), host);
    }

    private static HttpRequestMessage Signed(Vector v)
    {
        var req = new HttpRequestMessage(new HttpMethod(v.method), v.target);
        req.Headers.Add(GateSignatureMiddleware.TimestampHeader, v.timestamp.ToString());
        req.Headers.Add(GateSignatureMiddleware.NonceHeader, v.nonce);
        req.Headers.Add(GateSignatureMiddleware.DeviceHeader, v.device_id);
        req.Headers.Add(GateSignatureMiddleware.SignatureHeader, v.signature);
        return req;
    }

    [Fact]
    public async Task MiddlewareOnlyLetsSignedRequestsThrough()
    {
        var v = LoadVector();
        var policy = GatePolicy.From(new PluginConfiguration { GatePublicKeys = v.public_key });
        var (client, host) = await Start(policy, DateTimeOffset.FromUnixTimeSeconds(v.timestamp));
        using (host)
        {
            var unsigned = await client.GetAsync("/System/Info/Public");
            Assert.Equal(HttpStatusCode.Forbidden, unsigned.StatusCode);

            var ok = await client.SendAsync(Signed(v));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            Assert.Equal("jellyfin", await ok.Content.ReadAsStringAsync());

            var replay = await client.SendAsync(Signed(v));
            Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
        }
    }

    [Fact]
    public async Task MiddlewareFailsClosedOnBadConfigAndOpenWhenUnconfigured()
    {
        var (client, host) = await Start(GatePolicy.From(new PluginConfiguration { GatePublicKeys = "garbage" }), DateTimeOffset.UtcNow);
        using (host)
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync("/")).StatusCode);
        }

        (client, host) = await Start(null, DateTimeOffset.UtcNow);
        using (host)
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync("/")).StatusCode);
        }

        (client, host) = await Start(GatePolicy.From(new PluginConfiguration()), DateTimeOffset.UtcNow);
        using (host)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
        }
    }
}
