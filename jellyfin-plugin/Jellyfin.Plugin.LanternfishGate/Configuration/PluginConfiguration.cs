using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.LanternfishGate.Configuration;

/// <summary>Plugin settings.</summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Gets or sets the Gate public keys (base64, one per line), from
    /// `lanternfish-gate upstream-key`. Empty means not enforcing yet.
    /// </summary>
    public string GatePublicKeys { get; set; } = string.Empty;

    /// <summary>Gets or sets the allowed clock difference between Gate and Jellyfin, in seconds.</summary>
    public int MaxClockSkewSeconds { get; set; } = 30;

    /// <summary>Gets or sets a value indicating whether unsigned GET /health from this machine is allowed (Docker health checks).</summary>
    public bool AllowLoopbackHealthCheck { get; set; } = true;
}
