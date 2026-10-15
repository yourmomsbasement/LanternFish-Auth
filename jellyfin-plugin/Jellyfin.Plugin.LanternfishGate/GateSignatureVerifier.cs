using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Jellyfin.Plugin.LanternfishGate;

/// <summary>Outcome of checking a request's Gate signature.</summary>
public enum VerifyResult
{
    /// <summary>Signed by the Gate, fresh, and not seen before.</summary>
    Ok,

    /// <summary>One or more Gate headers are absent.</summary>
    Missing,

    /// <summary>A Gate header could not be parsed.</summary>
    Malformed,

    /// <summary>The timestamp is outside the allowed clock skew.</summary>
    Stale,

    /// <summary>The nonce has already been used.</summary>
    Replayed,

    /// <summary>The signature does not match any configured Gate key.</summary>
    BadSignature,

    /// <summary>Genuine, but the replay cache is full of unexpired nonces, so it can't be checked.</summary>
    Overloaded,
}

/// <summary>
/// Verifies the signature Lanternfish Gate puts on every request it forwards.
/// See docs/PROTOCOL.md in the LanternFish-Auth repository.
/// </summary>
public sealed class GateSignatureVerifier : IDisposable
{
    /// <summary>Context string that starts every signed message.</summary>
    public const string Context = "lanternfish-gate/v1/upstream\n";

    /// <summary>Default capacity of the replay cache.</summary>
    public const int DefaultMaxNonces = 200_000;

    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const int PruneIntervalSeconds = 10;

    private readonly ECDsa[] _keys;
    private readonly long _maxSkewSeconds;
    private readonly int _maxNonces;
    private readonly ConcurrentDictionary<string, long> _nonces = new(StringComparer.Ordinal);

    // ConcurrentDictionary.Count takes every lock, so keep our own count.
    private int _nonceCount;
    private long _nextPrune;
    private long _lastPrune = long.MinValue;
    private int _pruning;

    /// <summary>Initializes a new instance of the <see cref="GateSignatureVerifier"/> class.</summary>
    /// <param name="base64Keys">Gate public keys, base64 SubjectPublicKeyInfo. More than one allows rotation.</param>
    /// <param name="maxSkew">How far a request's timestamp may be from this server's clock.</param>
    /// <param name="maxNonces">Capacity of the replay cache.</param>
    public GateSignatureVerifier(IEnumerable<string> base64Keys, TimeSpan maxSkew, int maxNonces = DefaultMaxNonces)
    {
        var keys = new List<ECDsa>();
        foreach (var k in base64Keys)
        {
            keys.Add(ParseKey(k));
        }

        if (keys.Count == 0)
        {
            throw new ArgumentException("At least one Gate public key is required.", nameof(base64Keys));
        }

        _keys = keys.ToArray();
        _maxSkewSeconds = (long)maxSkew.TotalSeconds;
        _maxNonces = maxNonces;
    }

    /// <summary>Gets the number of nonces in the replay cache.</summary>
    public int NonceCount => Volatile.Read(ref _nonceCount);

    /// <summary>Gets the number of configured keys.</summary>
    public int KeyCount => _keys.Length;

    /// <summary>Parses a base64 P-256 SubjectPublicKeyInfo.</summary>
    /// <param name="base64">The key.</param>
    /// <returns>The key, ready for verification.</returns>
    public static ECDsa ParseKey(string base64)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(base64.Trim()), out _);
            if (ecdsa.ExportParameters(false).Curve.Oid.Value != P256Oid)
            {
                throw new FormatException("Gate public key must be ECDSA P-256.");
            }

            return ecdsa;
        }
        catch (CryptographicException ex)
        {
            ecdsa.Dispose();
            throw new FormatException("Gate public key is not a valid SubjectPublicKeyInfo.", ex);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    /// <summary>Builds the exact bytes the Gate signs.</summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="target">Raw request target (escaped path and query).</param>
    /// <param name="timestamp">Unix seconds.</param>
    /// <param name="nonce">Single-use nonce.</param>
    /// <param name="deviceId">Authenticated device ID.</param>
    /// <returns>The message bytes.</returns>
    public static byte[] Message(string method, string target, string timestamp, string nonce, string deviceId)
        => Encoding.UTF8.GetBytes(Context + method + "\n" + target + "\n" + timestamp + "\n" + nonce + "\n" + deviceId);

    /// <summary>Checks one request.</summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="target">Raw request target as received.</param>
    /// <param name="timestamp">X-Lanternfish-Gate-Timestamp.</param>
    /// <param name="nonce">X-Lanternfish-Gate-Nonce.</param>
    /// <param name="deviceId">X-Lanternfish-Device.</param>
    /// <param name="signature">X-Lanternfish-Gate-Signature.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The outcome.</returns>
    public VerifyResult Verify(string method, string target, string? timestamp, string? nonce, string? deviceId, string? signature, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(nonce) || deviceId is null || string.IsNullOrEmpty(signature))
        {
            return VerifyResult.Missing;
        }

        if (!long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var ts) || nonce.Length > 128)
        {
            return VerifyResult.Malformed;
        }

        var nowSeconds = now.ToUnixTimeSeconds();
        if (Math.Abs(nowSeconds - ts) > _maxSkewSeconds)
        {
            return VerifyResult.Stale;
        }

        byte[] sig;
        try
        {
            sig = Convert.FromBase64String(signature);
        }
        catch (FormatException)
        {
            return VerifyResult.Malformed;
        }

        if (sig.Length != 64)
        {
            return VerifyResult.Malformed;
        }

        var message = Message(method, target, timestamp, nonce, deviceId);
        var valid = false;
        foreach (var key in _keys)
        {
            // ECDsa instances are not documented as thread-safe.
            lock (key)
            {
                valid = key.VerifyData(message, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            if (valid)
            {
                break;
            }
        }

        if (!valid)
        {
            return VerifyResult.BadSignature;
        }

        // Only remember nonces of genuine requests, so junk can't fill the cache.
        PruneNonces(nowSeconds);
        if (_nonces.ContainsKey(nonce))
        {
            return VerifyResult.Replayed;
        }

        // SECURITY: the cache is capped. When it is full of unexpired nonces,
        // refuse rather than evict live entries, which would let their
        // requests be replayed.
        if (Interlocked.Increment(ref _nonceCount) > _maxNonces)
        {
            Interlocked.Decrement(ref _nonceCount);
            return VerifyResult.Overloaded;
        }

        if (_nonces.TryAdd(nonce, ts + _maxSkewSeconds))
        {
            return VerifyResult.Ok;
        }

        Interlocked.Decrement(ref _nonceCount);
        return VerifyResult.Replayed;
    }

    // Removes expired nonces every PruneIntervalSeconds, or sooner (at most
    // once a second) while the cache is full. Only one prune runs at a time,
    // so a full cache can't make every request scan it.
    private void PruneNonces(long nowSeconds)
    {
        var full = Volatile.Read(ref _nonceCount) >= _maxNonces;
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
                if (entry.Value < nowSeconds && _nonces.TryRemove(entry.Key, out _))
                {
                    Interlocked.Decrement(ref _nonceCount);
                }
            }
        }
        finally
        {
            Volatile.Write(ref _pruning, 0);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var key in _keys)
        {
            key.Dispose();
        }
    }
}
