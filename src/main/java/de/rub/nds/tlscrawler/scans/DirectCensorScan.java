/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.scans;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import de.rub.nds.censor.config.CensorScannerConfig;
import de.rub.nds.censor.constants.Ip;
import de.rub.nds.censor.execution.ServerScan;
import de.rub.nds.censor.execution.result.ServerScanResult;
import de.rub.nds.censor.ip.IpAddress;
import de.rub.nds.censor.ip.Ipv4Address;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlscrawler.constant.Status;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

public class DirectCensorScan extends Scan {

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final String outputFolder;

    private static final Logger LOGGER = LogManager.getLogger();

    public DirectCensorScan(ScanJob scanJob, long rabbitMqAckTag, RabbitMqOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider,
        String outputFolder) {
        super(scanJob, rabbitMqAckTag, orchestrationProvider, persistenceProvider);
        this.outputFolder = outputFolder;
    }

    @Override
    public void run() {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        CensorScannerConfig config = new CensorScannerConfig(generalDelegate);

        config.setOutputFolder(outputFolder);
        String ip = scanJob.getScanTarget().getIp();
        // TODO: change ip/hostname logic in censorscanner then we can simply pass the ip here
        Optional<Ip> ipOptional = Arrays.stream(Ip.values()).sequential().filter(x -> x.getAddress().equals(ip)).findAny();
        if (ipOptional.isEmpty()) {
            LOGGER.warn("Ip " + ip + " has no corresponding hostname in CensorScanner");
            return;
        }
        IpAddress chosenIp = new Ipv4Address(ipOptional.get().getAddress());
        String hostname = ipOptional.get().name();

        ServerScan serverScan = new ServerScan(hostname, chosenIp, config);
        LOGGER.info("Started scanning '{}' ({})", scanJob.getScanTarget(), scanJob.getScanConfig().getScannerDetail());
        ServerScanResult singleServerResult = serverScan.execute();
        LOGGER.info("Finished scanning '{}' ({}) in {} s", scanJob.getScanTarget(), scanJob.getScanConfig().getScannerDetail(),
            (singleServerResult.getScanEndTime() - singleServerResult.getScanStartTime()) / 1000);

        if (!cancelled.get()) {
            persistenceProvider.insertScanResult(new ScanResult(scanJob.getBulkScanId(), scanJob.getScanTarget(), this.createDocumentFromServerResult(singleServerResult)),
                scanJob.getDbName(), scanJob.getCollectionName());
            scanJob.setStatus(Status.DoneResultWritten);
        } else {
            scanJob.setStatus(Status.DoneNoResult);
        }
    }

    @Override
    public void cancel(boolean timeout) {
        if (!cancelled.getAndSet(true)) {
            if (timeout) {
                scanJob.setStatus(Status.Timeout);
            }
            if (scanJob.isMonitored()) {
                orchestrationProvider.notifyOfDoneScanJob(scanJob);
            }
            orchestrationProvider.sendAck(rabbitMqAckTag);
        }
    }

    private Document createDocumentFromServerResult(ServerScanResult result) {
        Document document = new Document();
        document.put("result", result);
        return document;
    }
}
