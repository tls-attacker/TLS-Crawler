/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlscrawler.config.delegate.CensorScanDelegate;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;
import de.rub.nds.tlscrawler.config.delegate.RabbitMqDelegate;
import de.rub.nds.tlscrawler.config.delegate.TlsScanDelegate;

public class WorkerCommandConfig {

    @ParametersDelegate private final RabbitMqDelegate rabbitMqDelegate;

    @ParametersDelegate private final MongoDbDelegate mongoDbDelegate;

    @ParametersDelegate private final TlsScanDelegate tlsScanDelegate;

    @ParametersDelegate private final CensorScanDelegate censorScanDelegate;

    @Parameter(
            names = "-numberOfThreads",
            description = "Number of worker threads the crawler slave should use")
    private int numberOfThreads = Runtime.getRuntime().availableProcessors();

    @Parameter(
            names = "-parallelProbeThreads",
            description = "Number of worker threads the crawler slave should use.")
    private int parallelProbeThreads = 20;

    @Parameter(
            names = "-scanTimeout",
            description =
                    "Overall timeout for one scan in ms. (Default 14 minutes)"
                            + "Has to be lower than rabbitMq consumerAck timeout (default 15min) or else rabbitMq connection will be closed if scan takes longer."
                            + "After the timeout the worker tries to shutdown the scan but a shutdown can not be guaranteed due to the TLS-Scanner implementation.")
    private int scanTimeout = 840000;

    public WorkerCommandConfig() {
        rabbitMqDelegate = new RabbitMqDelegate();
        mongoDbDelegate = new MongoDbDelegate();
        tlsScanDelegate = new TlsScanDelegate();
        censorScanDelegate = new CensorScanDelegate();
    }

    public RabbitMqDelegate getRabbitMqDelegate() {
        return rabbitMqDelegate;
    }

    public MongoDbDelegate getMongoDbDelegate() {
        return mongoDbDelegate;
    }

    public TlsScanDelegate getTlsScanDelegate() {
        return tlsScanDelegate;
    }

    public CensorScanDelegate getCensorScanDelegate() {
        return censorScanDelegate;
    }

    public int getNumberOfThreads() {
        return numberOfThreads;
    }

    public int getParallelProbeThreads() {
        return parallelProbeThreads;
    }

    public int getScanTimeout() {
        return scanTimeout;
    }
}
