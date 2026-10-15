using System;
using System.Net;
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

public class OrderingTests
{
    // Stands in for another plugin (like JellyFlix) that serves /web from its
    // own startup filter and was registered before this plugin.
    private sealed class OtherPluginWebHost : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                if (ctx.Request.Path.StartsWithSegments("/web"))
                {
                    await ctx.Response.WriteAsync("other plugin's web client");
                    return;
                }

                await nxt();
            });
            next(app);
        };
    }

    [Fact]
    public async Task SignatureCheckRunsBeforeOtherPluginsStartupFilters()
    {
        using var gateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var policy = GatePolicy.From(new PluginConfiguration { GatePublicKeys = Convert.ToBase64String(gateKey.ExportSubjectPublicKeyInfo()) });

        using var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(s =>
                {
                    s.AddSingleton<IStartupFilter, OtherPluginWebHost>(); // registered first, like an earlier plugin
                    new PluginServiceRegistrator().RegisterServices(s, null!);
                    s.AddSingleton<Func<GatePolicy?>>(() => policy);
                })
                .Configure(app => app.Run(ctx => ctx.Response.WriteAsync("jellyfin"))))
            .StartAsync();

        var resp = await host.GetTestClient().GetAsync("/web/index.html");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
