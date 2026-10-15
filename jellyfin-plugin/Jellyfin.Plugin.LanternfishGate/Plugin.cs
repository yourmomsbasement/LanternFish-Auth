using System;
using System.Collections.Generic;
using System.Globalization;
using Jellyfin.Plugin.LanternfishGate.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>Only accept requests that Lanternfish Gate forwarded and signed.</summary>
public sealed class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    private volatile GatePolicy _policy;

    /// <summary>Initializes a new instance of the <see cref="Plugin"/> class.</summary>
    /// <param name="applicationPaths">Application paths.</param>
    /// <param name="xmlSerializer">XML serializer.</param>
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        _policy = GatePolicy.From(Configuration);
        ConfigurationChanged += (_, _) => _policy = GatePolicy.From(Configuration);
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
