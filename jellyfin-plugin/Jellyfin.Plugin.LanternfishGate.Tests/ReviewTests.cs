using System;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Plugin.LanternfishGate.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.LanternfishGate.Tests;

// Regression tests for the plugin findings of the 2026-10-17 review.
public class ReviewTests
{
    private static string Sign(ECDsa key, string nonce, string device, long ts) =>
        Convert.ToBase64String(key.SignData(
            GateSignatureVerifier.Message("GET", "/Items", ts.ToString(), nonce, device),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    // M1: one device filling its share is refused (429); the others aren't.
    [Fact]
    public void ReplayCacheHasPerDeviceQuota()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var verifier = new GateSignatureVerifier([Convert.ToBase64String(key.ExportSubjectPublicKeyInfo())], TimeSpan.FromSeconds(30), cache: new ReplayCache(10, 3));
        var now = DateTimeOffset.UtcNow;
        var ts = now.ToUnixTimeSeconds();
        VerifyResult Send(string nonce, string device) => verifier.Verify("GET", "/Items", ts.ToString(), nonce, device, Sign(key, nonce, device, ts), now);

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(VerifyResult.Ok, Send("a" + i, "dev_busy"));
        }

        Assert.Equal(VerifyResult.DeviceOverloaded, Send("a3", "dev_busy"));
        Assert.Equal(VerifyResult.Ok, Send("b0", "dev_other"));
        Assert.Equal(VerifyResult.Replayed, Send("a0", "dev_busy"));
        Assert.Equal(4, verifier.NonceCount);

        // Once its nonces expire, the device has room again.
        var later = now.AddSeconds(31);
        var ts2 = later.ToUnixTimeSeconds();
        Assert.Equal(VerifyResult.Ok, verifier.Verify("GET", "/Items", ts2.ToString(), "a4", "dev_busy", Sign(key, "a4", "dev_busy", ts2), later));
    }

    // L4: saving the settings doesn't open a replay window.
    [Fact]
    public void ReplayCacheSurvivesConfigurationChange()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var config = new PluginConfiguration { GatePublicKeys = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) };
        var cache = new ReplayCache();
        var before = GatePolicy.From(config, cache);
        var after = GatePolicy.From(config, cache);
        var now = DateTimeOffset.UtcNow;
        var ts = now.ToUnixTimeSeconds();
        var sig = Sign(key, "n1", "dev", ts);
        Assert.Equal(VerifyResult.Ok, before.Verifier!.Verify("GET", "/Items", ts.ToString(), "n1", "dev", sig, now));
        Assert.Equal(VerifyResult.Replayed, after.Verifier!.Verify("GET", "/Items", ts.ToString(), "n1", "dev", sig, now));
    }

    // L8: only exactly /health as sent, and only while nothing forwarded
    // the address. (Driven directly: HttpClient would normalize /he%61lth.)
    [Fact]
    public async Task HealthExemptionIsExact()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var policy = GatePolicy.From(new PluginConfiguration
        {
            GatePublicKeys = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            AllowLoopbackHealthCheck = true,
        });
        var middleware = new GateSignatureMiddleware(_ => Task.CompletedTask, () => policy, NullLogger<GateSignatureMiddleware>.Instance);

        async Task<int> Get(string path, string rawTarget, string? header = null)
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = "GET";
            ctx.Request.Path = path;
            ctx.Features.Get<IHttpRequestFeature>()!.RawTarget = rawTarget;
            ctx.Connection.RemoteIpAddress = IPAddress.Loopback;
            if (header is not null)
            {
                ctx.Request.Headers[header] = "203.0.113.9";
            }

            ctx.Response.Body = new System.IO.MemoryStream();
            await middleware.InvokeAsync(ctx);
            return ctx.Response.StatusCode;
        }

        Assert.Equal(200, await Get("/health", "/health"));
        Assert.Equal(403, await Get("/health", "/he%61lth"));
        Assert.Equal(403, await Get("/Foo/health", "/Foo/health"));
        Assert.Equal(403, await Get("/health", "/health?x=1"));
        Assert.Equal(403, await Get("/health", "/health", "X-Original-For"));
        Assert.Equal(403, await Get("/health", "/health", "X-Forwarded-For"));
    }

    // L9: a second X-Lanternfish-Auth value (added on the internal hop)
    // doesn't switch the script on.
    [Fact]
    public void RenewalNeedsASingleAuthHeader()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = "/web/index.html";
        ctx.Request.Headers[SessionRenewal.AuthHeader] = "cookie";
        Assert.True(SessionRenewal.Applies(ctx.Request));
        ctx.Request.Headers[SessionRenewal.AuthHeader] = new Microsoft.Extensions.Primitives.StringValues(["session", "cookie"]);
        Assert.False(SessionRenewal.Applies(ctx.Request));
    }
}
