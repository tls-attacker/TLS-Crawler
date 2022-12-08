/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.censor.constants.ConnectionPreset;
import de.rub.nds.tlscrawler.config.WorkerCommandConfig;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.DirectCensorScan;
import de.rub.nds.tlscrawler.scans.PingScan;
import de.rub.nds.tlscrawler.scans.Scan;
import de.rub.nds.tlscrawler.scans.TlsScan;
import java.util.List;
import java.util.concurrent.*;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Worker that subscribe to scan job queue, initializes thread pool and submits received scan jobs
 * to thread pool.
 */
public class Worker extends TlsCrawler {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int maxThreadCount;
    private final int parallelProbeThreads;
    private final int scanTimeout;
    // TODO: tidy up what belongs to ScanJob, ScanConfig and the Scan objects
    private final String outputFolder;
    private final List<ConnectionPreset> connectionPresets;

    private final ThreadPoolExecutor executor;
    private final ThreadPoolExecutor timeoutExecutor;

    /**
     * TLS-Crawler constructor.
     *
     * @param commandConfig The config for this worker.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     */
    public Worker(
            WorkerCommandConfig commandConfig,
            RabbitMqOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider) {
        super(orchestrationProvider, persistenceProvider);
        this.maxThreadCount = commandConfig.getNumberOfThreads();
        this.parallelProbeThreads = commandConfig.getParallelProbeThreads();
        this.scanTimeout = commandConfig.getScanTimeout();
        this.outputFolder = commandConfig.getCensorScanDelegate().getOutputFolder();
        this.connectionPresets = commandConfig.getCensorScanDelegate().getConnectionPresets();

        executor =
                new ThreadPoolExecutor(
                        maxThreadCount,
                        maxThreadCount,
                        5,
                        TimeUnit.MINUTES,
                        new LinkedBlockingDeque<>());
        timeoutExecutor =
                new ThreadPoolExecutor(
                        maxThreadCount,
                        maxThreadCount,
                        5,
                        TimeUnit.MINUTES,
                        new LinkedBlockingDeque<>());
    }

    public void start() {
        this.orchestrationProvider.registerScanJobConsumer(
                ((scanJob, deliveryTag) -> {
                    switch (scanJob.getScanConfig().getScanType()) {
                        case TLS:
                            this.submitWithTimeout(
                                    new TlsScan(
                                            scanJob,
                                            deliveryTag,
                                            orchestrationProvider,
                                            persistenceProvider,
                                            parallelProbeThreads));
                            break;
                        case TLS_CENSOR_DIRECT:
                            this.submitWithTimeout(new DirectCensorScan(scanJob, deliveryTag, orchestrationProvider, persistenceProvider, outputFolder, connectionPresets));
                        case TLS_CENSOR_ECHO:
                            throw new NotImplementedException("Not implemented yet!");
                        case PING:
                            this.submitWithTimeout(
                                    new PingScan(
                                            scanJob,
                                            deliveryTag,
                                            orchestrationProvider,
                                            persistenceProvider));
                            break;
                    }
                }),
                this.maxThreadCount);
    }

    private void submitWithTimeout(Scan scan) {
        timeoutExecutor.submit(
                () -> {
                    Future<?> future = null;
                    try {
                        future = executor.submit(scan);
                        future.get(this.scanTimeout, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException | ExecutionException e) {
                        LOGGER.error("Could not submit a scan to the worker thread with error ", e);
                    } catch (TimeoutException e) {
                        LOGGER.info(
                                "Trying to shutdown scan of '{}' because timeout reached",
                                scan.getScanJob().getScanTarget());
                        scan.cancel(true);
                        future.cancel(true);
                    }
                });
    }
}
