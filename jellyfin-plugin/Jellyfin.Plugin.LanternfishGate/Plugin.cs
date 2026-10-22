using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.LanternfishGate.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>Only accept requests that Lanternfish Gate forwarded and signed.</summary>
public sealed class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    // SECURITY (L4): one replay cache for the plugin's life. A settings
    // save builds a new verifier, and a fresh cache would let a request seen
    // just before the save be replayed just after it.
    private readonly ReplayCache _replayCache = new();
    private volatile GatePolicy _policy;

    /// <summary>Initializes a new instance of the <see cref="Plugin"/> class.</summary>
    /// <param name="applicationPaths">Application paths.</param>
    /// <param name="xmlSerializer">XML serializer.</param>
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        _policy = GatePolicy.From(Configuration, _replayCache);
        ConfigurationChanged += (_, _) => Replace(GatePolicy.From(Configuration, _replayCache));
        Instance = this;
    }

    /// <summary>Gets the running plugin instance.</summary>
    public static Plugin? Instance { get; private set; }

    /// <inheritdoc />
    public override string Name => "Lanternfish Gate";

    /// <inheritdoc />
    public override Guid Id => Guid.Parse("2ffdcd88-4b14-41c3-b3af-a2bdffb9506c");

    /// <inheritdoc />
    public override string Description => "Rejects every request that was not forwarded and signed by Lanternfish Gate.";

    /// <summary>Gets the policy for the current configuration.</summary>
    public GatePolicy Policy => _policy;

    // Swaps in a new policy and disposes the old verifier's keys once
    // requests that already picked it up are done with it (verification is
    // synchronous, so a minute is ample).
    private void Replace(GatePolicy next)
    {
        var old = Interlocked.Exchange(ref _policy, next);
        if (old.Verifier is { } verifier)
        {
            _ = Task.Delay(TimeSpan.FromMinutes(1)).ContinueWith(_ => verifier.Dispose(), TaskScheduler.Default);
        }
    }

    /// <inheritdoc />
    public IEnumerable<PluginPageInfo> GetPages() =>
    [
        new PluginPageInfo
        {
            Name = Name,
            EmbeddedResourcePath = string.Format(CultureInfo.InvariantCulture, "{0}.Configuration.configPage.html", GetType().Namespace),
        },
    ];
}
