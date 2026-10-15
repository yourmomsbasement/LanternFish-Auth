using System;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>The enforcement settings in effect for the current configuration.</summary>
public sealed class GatePolicy
{
    /// <summary>Gets the verifier, or null when no Gate key is configured yet.</summary>
    public GateSignatureVerifier? Verifier { get; init; }

    /// <summary>Gets the configuration error, if the configured keys could not be used.</summary>
    public string? ConfigError { get; init; }

    /// <summary>Gets a value indicating whether unsigned GET /health from loopback is allowed.</summary>
    public bool AllowLoopbackHealthCheck { get; init; }

    /// <summary>Gets a value indicating whether the plugin adds the Gate's session-renewal script to the web client.</summary>
    public bool InjectSessionRenewal { get; init; }

    /// <summary>Builds the policy for a configuration.</summary>
    /// <param name="config">The plugin configuration.</param>
    /// <returns>The policy.</returns>
    public static GatePolicy From(Configuration.PluginConfiguration config)
    {
        var keys = config.GatePublicKeys.Split(['\n', '\r', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (keys.Length == 0)
        {
            return new GatePolicy { AllowLoopbackHealthCheck = config.AllowLoopbackHealthCheck, InjectSessionRenewal = config.InjectSessionRenewal };
        }

        try
        {
            var skew = TimeSpan.FromSeconds(Math.Clamp(config.MaxClockSkewSeconds, 5, 300));
            return new GatePolicy
            {
                Verifier = new GateSignatureVerifier(keys, skew),
                AllowLoopbackHealthCheck = config.AllowLoopbackHealthCheck,
                InjectSessionRenewal = config.InjectSessionRenewal,
            };
        }
        catch (FormatException ex)
        {
            return new GatePolicy { ConfigError = ex.Message, AllowLoopbackHealthCheck = config.AllowLoopbackHealthCheck, InjectSessionRenewal = config.InjectSessionRenewal };
        }
    }
}
