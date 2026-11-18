using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using VirtoCommerce.Platform.Core.DistributedLock;

namespace VirtoCommerce.Otp.Tests;

public sealed class TestDistributedLock : IDistributedLock
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _semaphores = new();

    public ConcurrentQueue<string> AcquiredResources { get; } = new();

    public Task<IDistributedLockHandle> AcquireAsync(string resource, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        return TryAcquireAsync(resource, Timeout.InfiniteTimeSpan, cancellationToken);
    }

    public async Task<IDistributedLockHandle> TryAcquireAsync(string resource, TimeSpan timeout = default, CancellationToken cancellationToken = default)
    {
        var semaphore = _semaphores.GetOrAdd(resource, _ => new SemaphoreSlim(1, 1));
        if (!await semaphore.WaitAsync(timeout, cancellationToken))
        {
            return null;
        }

        AcquiredResources.Enqueue(resource);

        return new Handle(resource, semaphore);
    }

    private sealed class Handle(string resource, SemaphoreSlim semaphore) : IDistributedLockHandle
    {
        private int _released;

        public string Resource { get; } = resource;

        public CancellationToken HandleLostToken => CancellationToken.None;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                semaphore.Release();
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
