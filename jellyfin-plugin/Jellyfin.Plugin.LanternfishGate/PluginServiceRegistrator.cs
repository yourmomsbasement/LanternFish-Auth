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
        serviceCollection.AddTransient<IStartupFilter, GateStartupFilter>();
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
