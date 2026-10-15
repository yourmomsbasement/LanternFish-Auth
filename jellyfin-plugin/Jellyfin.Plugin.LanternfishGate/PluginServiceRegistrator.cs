using System;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>Puts the signature check in front of Jellyfin's whole request pipeline.</summary>
public sealed class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<Func<GatePolicy?>>(() => Plugin.Instance?.Policy);

        // Startup filters wrap each other in registration order, the first
        // outermost. Plugins register in load order, so another plugin's
        // filter (one serving /web, say) would otherwise run before the
        // signature check. Going first makes the check cover everything.
        serviceCollection.Insert(0, ServiceDescriptor.Transient<IStartupFilter, GateStartupFilter>());
    }

    private sealed class GateStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.UseMiddleware<GateSignatureMiddleware>();
            next(app);
        };
    }
}
