using System;
using System.Collections.Concurrent;
using System.Threading;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>
/// Nonces of genuine Gate requests, kept until their timestamp can no longer
/// pass the clock-skew check.
/// </summary>
/// <remarks>
/// SECURITY: capped in total and per device. When either is full of live
/// nonces, new requests are refused rather than live entries evicted, which
/// would let their requests be replayed. The per-device cap keeps one busy
/// (or hostile) device from filling the cache and refusing everyone (M1 of
/// the 2026-10-17 review). The cache outlives configuration changes: a new
/// verifier built on a settings save keeps it, so a request seen before the
/// save can't be replayed after it (L4).
/// </remarks>
public sealed class ReplayCache
{
    /// <summary>Default capacity.</summary>
    public const int DefaultMaxNonces = 200_000;

    /// <summary>Default capacity for one device.</summary>
    public const int DefaultMaxPerDevice = 10_000;

    private const int PruneIntervalSeconds = 10;

    private readonly int _maxNonces;
    private readonly int _maxPerDevice;
    private readonly ConcurrentDictionary<string, Entry> _nonces = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _perDevice = new(StringComparer.Ordinal);

    // ConcurrentDictionary.Count takes every lock, so keep our own count.
    private int _count;
    private long _nextPrune;
    private long _lastPrune = long.MinValue;
    private int _pruning;

    /// <summary>Initializes a new instance of the <see cref="ReplayCache"/> class.</summary>
    /// <param name="maxNonces">Capacity.</param>
    /// <param name="maxPerDevice">Capacity for one device; at most <paramref name="maxNonces"/>.</param>
    public ReplayCache(int maxNonces = DefaultMaxNonces, int maxPerDevice = DefaultMaxPerDevice)
    {
        _maxNonces = maxNonces;
        _maxPerDevice = Math.Min(maxPerDevice, maxNonces);
    }

    /// <summary>Outcome of recording a nonce.</summary>
    public enum Outcome
    {
        /// <summary>Recorded: first use.</summary>
        Added,

        /// <summary>Already seen.</summary>
        Replayed,

        /// <summary>The cache is full of live nonces.</summary>
        Full,

        /// <summary>This device's share is full of live nonces.</summary>
        DeviceFull,
    }

    /// <summary>Gets the number of nonces held.</summary>
    public int Count => Volatile.Read(ref _count);

    /// <summary>Records a nonce, unless seen before or there is no room.</summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="deviceId">The signed device ID.</param>
    /// <param name="expires">Unix seconds after which it can be forgotten.</param>
    /// <param name="nowSeconds">The current time, Unix seconds.</param>
    /// <returns>The outcome.</returns>
    public Outcome TryAdd(string nonce, string deviceId, long expires, long nowSeconds)
    {
        Prune(nowSeconds);
        if (_nonces.ContainsKey(nonce))
        {
            return Outcome.Replayed;
        }

        if (Interlocked.Increment(ref _count) > _maxNonces)
        {
            Interlocked.Decrement(ref _count);
            return Outcome.Full;
        }

        if (_perDevice.AddOrUpdate(deviceId, 1, (_, n) => n + 1) > _maxPerDevice)
        {
            Release(deviceId);
            return Outcome.DeviceFull;
        }

        if (_nonces.TryAdd(nonce, new Entry(expires, deviceId)))
        {
            return Outcome.Added;
        }

        Release(deviceId);
        return Outcome.Replayed;
    }

    private void Release(string deviceId)
    {
        Interlocked.Decrement(ref _count);
        _perDevice.AddOrUpdate(deviceId, 0, (_, n) => n - 1);
        _perDevice.TryRemove(new System.Collections.Generic.KeyValuePair<string, int>(deviceId, 0));
    }

    // Removes expired nonces every PruneIntervalSeconds, or sooner (at most
    // once a second) while the cache is full. Only one prune runs at a time,
    // so a full cache can't make every request scan it.
    private void Prune(long nowSeconds)
    {
        var full = Volatile.Read(ref _count) >= _maxNonces;
        if (nowSeconds < Interlocked.Read(ref _nextPrune) && !(full && nowSeconds > Interlocked.Read(ref _lastPrune)))
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _pruning, 1, 0) != 0)
        {
            return;
        }

        try
        {
            Interlocked.Exchange(ref _lastPrune, nowSeconds);
            Interlocked.Exchange(ref _nextPrune, nowSeconds + PruneIntervalSeconds);
            foreach (var entry in _nonces)
            {
                if (entry.Value.Expires < nowSeconds && _nonces.TryRemove(entry.Key, out var removed))
                {
                    Release(removed.DeviceId);
                }
            }
        }
        finally
        {
            Volatile.Write(ref _pruning, 0);
        }
    }

    private readonly record struct Entry(long Expires, string DeviceId);
}
