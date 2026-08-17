// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.Configuration;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Performs configuration retrieval on a dedicated background thread.
    /// </summary>
    /// <typeparam name="T">The configuration type.</typeparam>
    public sealed class DedicatedThreadRetriever<T> where T : class
    {
        private readonly object _stateLock = new();
        private readonly AutoResetEvent _refreshRequested = new(false);
        private readonly IConfigurationRetriever<T> _configRetrieverAsync;
        private readonly IConfigurationRetrieverSync<T> _configRetrieverSync;
        private readonly IDocumentRetriever _docRetrieverAsync;
        private readonly IDocumentRetrieverSync _docRetrieverSync;
        private readonly IConfigurationValidator<T> _configValidator;
        private readonly bool _useAsyncRetrieval;
        private Func<string> _metadataAddressProvider;
        private Action<T, DateTimeOffset> _publish;
        private Action<Exception> _reportFailure;
        private RefreshOperation _activeOperation;
        private Thread _worker;

        internal bool UsesAsyncRetrieval => _useAsyncRetrieval;

        /// <summary>
        /// Instantiates a new <see cref="DedicatedThreadRetriever{T}"/>.
        /// </summary>
        /// <param name="metadataAddress">The address from which configuration is retrieved.</param>
        /// <param name="configurationRetriever">The <see cref="IConfigurationRetriever{T}"/> used to retrieve configuration asynchronously.</param>
        /// <param name="documentRetriever">The <see cref="IDocumentRetriever"/> used by <paramref name="configurationRetriever"/>.</param>
        /// <param name="configurationValidator">An optional <see cref="IConfigurationValidator{T}"/>.</param>
        public DedicatedThreadRetriever(
            string metadataAddress,
            IConfigurationRetriever<T> configurationRetriever,
            IDocumentRetriever documentRetriever,
            IConfigurationValidator<T> configurationValidator = null)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw new ArgumentNullException(nameof(metadataAddress));
            if (configurationRetriever is null)
                throw new ArgumentNullException(nameof(configurationRetriever));
            if (documentRetriever is null)
                throw new ArgumentNullException(nameof(documentRetriever));

            _metadataAddressProvider = () => metadataAddress;
            _configRetrieverAsync = configurationRetriever;
            _docRetrieverAsync = documentRetriever;
            _configValidator = configurationValidator;
            _useAsyncRetrieval = true;
        }

        private DedicatedThreadRetriever(
            string metadataAddress,
            IConfigurationRetrieverSync<T> configurationRetriever,
            IDocumentRetrieverSync documentRetriever,
            IConfigurationValidator<T> configurationValidator)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw new ArgumentNullException(nameof(metadataAddress));
            if (configurationRetriever is null)
                throw new ArgumentNullException(nameof(configurationRetriever));
            if (documentRetriever is null)
                throw new ArgumentNullException(nameof(documentRetriever));

            _metadataAddressProvider = () => metadataAddress;
            _configRetrieverSync = configurationRetriever;
            _docRetrieverSync = documentRetriever;
            _configValidator = configurationValidator;
            _useAsyncRetrieval = false;
        }

        /// <summary>
        /// Creates a <see cref="DedicatedThreadRetriever{T}"/> that uses synchronous configuration retrieval.
        /// </summary>
        /// <param name="metadataAddress">The address from which configuration is retrieved.</param>
        /// <param name="configurationRetriever">The <see cref="IConfigurationRetrieverSync{T}"/> used to retrieve configuration synchronously.</param>
        /// <param name="documentRetriever">The <see cref="IDocumentRetrieverSync"/> used by <paramref name="configurationRetriever"/>.</param>
        /// <param name="configurationValidator">An optional <see cref="IConfigurationValidator{T}"/>.</param>
        /// <returns>A dedicated-thread retriever configured for synchronous retrieval.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Design",
            "CA1000:DoNotDeclareStaticMembersOnGenericTypes",
            Justification = "Provides a synchronous-only construction path without ambiguous constructor overloads.")]
        internal static DedicatedThreadRetriever<T> CreateSync(
            string metadataAddress,
            IConfigurationRetrieverSync<T> configurationRetriever,
            IDocumentRetrieverSync documentRetriever,
            IConfigurationValidator<T> configurationValidator = null)
        {
            return new DedicatedThreadRetriever<T>(
                metadataAddress,
                configurationRetriever,
                documentRetriever,
                configurationValidator);
        }

        internal void Attach(
            Func<string> metadataAddressProvider,
            Action<T, DateTimeOffset> publish,
            Action<Exception> reportFailure)
        {
            lock (_stateLock)
            {
                if (_activeOperation is not null || (_worker is not null && _worker.IsAlive))
                    throw new InvalidOperationException("The dedicated retriever cannot be attached after retrieval has started.");

                _metadataAddressProvider = metadataAddressProvider;
                _publish = publish;
                _reportFailure = reportFailure;
            }
        }

        // this technically can run even if not Attach()'ed to a BackgroundConfigurationManager, though this is not intended use
        // if desired, can add some sort of _isAttached() flag to enforce this usage
        internal RefreshOperation RequestRefresh()
        {
            RefreshOperation operation = Volatile.Read(ref _activeOperation);
            if (operation is not null && !operation.IsCompleted)
                return operation;

            lock (_stateLock)
            {
                EnsureWorkerIsRunning();

                if (_activeOperation is null || _activeOperation.IsCompleted)
                {
                    Volatile.Write(ref _activeOperation, new RefreshOperation());
                    _refreshRequested.Set();
                }

                return _activeOperation;
            }
        }

        internal T RequestRefreshAndWait(CancellationToken cancellationToken)
        {
            return RequestRefresh().Wait(cancellationToken);
        }

        internal Task<T> RequestRefreshAndWaitAsync(CancellationToken cancellationToken)
        {
            return RequestRefresh().WaitAsync(cancellationToken);
        }

        private void EnsureWorkerIsRunning()
        {
            if (_worker is not null && _worker.IsAlive)
                return;

            if (_activeOperation is not null && !_activeOperation.IsCompleted)
            {
                _activeOperation.SetException(
                    new InvalidOperationException("The dedicated configuration retrieval thread stopped unexpectedly."));
                Volatile.Write(ref _activeOperation, null);
            }

            StartWorker();
        }

        private void StartWorker()
        {
            _worker = new Thread(Run)
            {
                IsBackground = true,
                Name = $"IdentityModel configuration retriever ({typeof(T).Name})"
            };
            _worker.Start();
        }

        // there is a theoretical race condition under async retrieval where the Thread can fire off a RetrieveAsync,
        // then get interrupted, then as a new Thread spawns, it fires off another RetrieveAsync, and these duplicate
        // requests may result in a race
        private void Run()
        {
            try
            {
                while (true)
                {
                    try
                    {
                        _refreshRequested.WaitOne();
                    }
                    catch (ThreadInterruptedException)
                    {
                        return;
                    }

                    RefreshOperation operation = Volatile.Read(ref _activeOperation);

                    if (operation is null || operation.IsCompleted)
                        continue;

                    if (_useAsyncRetrieval)
                        _ = RetrieveAsync(operation);
                    else
                        RetrieveSync(operation);
                }
            }
            finally
            {
                lock (_stateLock)
                {
                    if (ReferenceEquals(_worker, Thread.CurrentThread))
                    {
                        _worker = null;

                        if (_activeOperation is not null && !_activeOperation.IsCompleted)
                        {
                            StartWorker();
                            _refreshRequested.Set();
                        }
                    }
                }
            }
        }

        private void RetrieveSync(RefreshOperation operation)
        {
            try
            {
                T configuration = _configRetrieverSync.GetConfigurationSync(
                    _metadataAddressProvider(),
                    _docRetrieverSync,
                    CancellationToken.None);

                CompleteOperation(operation, configuration);
            }
#pragma warning disable CA1031 // The retriever extension point can throw any exception.
            catch (Exception ex)
            {
                FailOperation(operation, ex);
            }
#pragma warning restore CA1031
        }

        private async Task RetrieveAsync(RefreshOperation operation)
        {
            try
            {
                T configuration = await _configRetrieverAsync
                    .GetConfigurationAsync(
                        _metadataAddressProvider(),
                        _docRetrieverAsync,
                        CancellationToken.None)
                    .ConfigureAwait(false);

                CompleteOperation(operation, configuration);
            }
#pragma warning disable CA1031 // The retriever extension point can throw any exception.
            catch (Exception ex)
            {
                FailOperation(operation, ex);
            }
#pragma warning restore CA1031
        }

        private void CompleteOperation(RefreshOperation operation, T configuration)
        {
            if (_configValidator is not null)
            {
                ConfigurationValidationResult result = _configValidator.Validate(configuration);
                if (!result.Succeeded)
                {
                    FailOperation(operation, new InvalidConfigurationException(result.ErrorMessage));
                    return;
                }
            }

            _publish?.Invoke(configuration, DateTimeOffset.UtcNow);
            operation.SetResult(configuration);
            ClearActiveOperation(operation);
        }

        private void FailOperation(RefreshOperation operation, Exception exception)
        {
            _reportFailure?.Invoke(exception);
            operation.SetException(exception);
            ClearActiveOperation(operation);
        }

        private void ClearActiveOperation(RefreshOperation operation)
        {
            lock (_stateLock)
            {
                if (ReferenceEquals(_activeOperation, operation))
                    Volatile.Write(ref _activeOperation, null);
            }
        }

        internal sealed class RefreshOperation
        {
            private readonly ManualResetEventSlim _completion = new(false);
            private readonly TaskCompletionSource<T> _completionTask =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
            private T _configuration;
            private Exception _exception;

            internal bool IsCompleted => _completion.IsSet;

            internal T Wait(CancellationToken cancellationToken)
            {
                _completion.Wait(cancellationToken);

                if (_exception is not null)
                    ExceptionDispatchInfo.Capture(_exception).Throw();

                return _configuration;
            }

#pragma warning disable VSTHRD003 // The task is completed by the dedicated worker with asynchronous continuations.
            internal Task<T> WaitAsync(CancellationToken cancellationToken)
            {
                if (!cancellationToken.CanBeCanceled)
                    return _completionTask.Task;

                return WaitWithCancellationAsync(cancellationToken);
            }

            internal void SetResult(T configuration)
            {
                _configuration = configuration;
                _completionTask.TrySetResult(configuration);
                _completion.Set();
            }

            internal void SetException(Exception exception)
            {
                _exception = exception;
                _completionTask.TrySetException(exception);
                _completion.Set();
            }

            private async Task<T> WaitWithCancellationAsync(CancellationToken cancellationToken)
            {
                var cancellationTask = new TaskCompletionSource<bool>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                using (cancellationToken.Register(
                    state => ((TaskCompletionSource<bool>)state).TrySetResult(true),
                    cancellationTask))
                {
                    Task completedTask = await Task.WhenAny(
                        _completionTask.Task,
                        cancellationTask.Task).ConfigureAwait(false);
                    if (completedTask != _completionTask.Task)
                        throw new OperationCanceledException(cancellationToken);

                    return await _completionTask.Task.ConfigureAwait(false);
                }
            }
#pragma warning restore VSTHRD003
        }
    }
}
