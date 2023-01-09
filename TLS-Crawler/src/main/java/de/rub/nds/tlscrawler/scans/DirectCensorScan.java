/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.censor.config.CensorScannerConfig;
import de.rub.nds.censor.execution.ServerScan;
import de.rub.nds.censor.execution.result.ServerScanResult;
import de.rub.nds.censor.network.*;
import de.rub.nds.tlscrawler.constant.Status;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import inet.ipaddr.IPAddressString;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

public class DirectCensorScan extends Scan {

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final String ipRangeFile;
    private final CensorScannerConfig censorScannerConfig;

    private static final Logger LOGGER = LogManager.getLogger();

    public DirectCensorScan(
            ScanJob scanJob,
            long rabbitMqAckTag,
            RabbitMqOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            String ipRangeFile,
            CensorScannerConfig censorScannerConfig) {
        super(scanJob, rabbitMqAckTag, orchestrationProvider, persistenceProvider);
        this.ipRangeFile = ipRangeFile;
        this.censorScannerConfig = censorScannerConfig;
    }

    @Override
    public void run() {
        try {
            String ip = scanJob.getScanTarget().getIp();

            IpAddress chosenIp = new Ipv4Address(ip);
            ServerNetworkInformation serverNetworkInformation =
                    new ServerNetworkInformation(
                            chosenIp, getRoutesForIp(ipRangeFile, ip), "unknown");

            ServerScan serverScan = new ServerScan(serverNetworkInformation, censorScannerConfig);
            LOGGER.info(
                    "Started scanning '{}' ({})",
                    scanJob.getScanTarget(),
                    scanJob.getScanConfig().getScannerDetail());
            ServerScanResult singleServerResult = serverScan.execute();
            LOGGER.info(
                    "Finished scanning '{}' ({}) in {} s",
                    scanJob.getScanTarget(),
                    scanJob.getScanConfig().getScannerDetail(),
                    (singleServerResult.getScanEndTime() - singleServerResult.getScanStartTime())
                            / 1000);

            if (!cancelled.get()) {
                persistenceProvider.insertScanResult(
                        new ScanResult(
                                scanJob.getBulkScanId(),
                                scanJob.getScanTarget(),
                                this.createDocumentFromServerResult(singleServerResult)),
                        scanJob.getDbName(),
                        scanJob.getCollectionName());
                scanJob.setStatus(Status.DoneResultWritten);
            } else {
                LOGGER.warn(
                        "Scanning of {} had to be aborted because of a timeout: ",
                        scanJob.getScanTarget());
                scanJob.setStatus(Status.DoneNoResult);
            }
        } catch (Throwable e) {
            LOGGER.error(
                    "Scanning of {} had to be aborted because of an exception: ",
                    scanJob.getScanTarget(),
                    e);
        } finally {
            this.cancel(false);
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

    /**
     * Returns a list of IP ranges/routes for the given IP Address. Sorts the list by containment of
     * Ip address in different ranges and their size.
     *
     * @param ipRangeFile The file containing information about ipRanges and their Autonomous
     *     Systems
     * @param ip Ip Address to get autonomous systems for
     * @return List of {@link IpRange} sorted by their size
     */
    private List<IpRange> getRoutesForIp(String ipRangeFile, String ip) {

        List<IpRange> ipRanges = new LinkedList<>();
        List<String> ipRangesData;
        try (Stream<String> lines = Files.lines(Paths.get(ipRangeFile))) {
            ipRangesData = lines.collect(Collectors.toList());
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + ipRangeFile, ex);
        }

        for (String ipRangeData : ipRangesData) {
            String[] data = ipRangeData.split("\\|");
            String ipRange = data[0];
            String ipRangeInformation = (data.length > 1 ? data[1] : "-1");
            String countryCode = (data.length > 2 ? data[2] : "");
            String asNumber = (data.length > 3 ? data[3] : "-1");
            String asName = (data.length > 4 ? data[4] : "");
            String asInformation = (data.length > 5 ? data[5] : "");

            if (new IPAddressString(ipRange).contains(new IPAddressString(ip))) {
                AutonomousSystem autonomousSystem =
                        new AutonomousSystem(
                                Integer.parseInt(asNumber), countryCode, asInformation, asName);
                ipRanges.add(new IpRange(ipRange, ipRangeInformation, autonomousSystem));
            }
        }

        ipRanges.sort(
                (o1, o2) -> {
                    IPAddressString range1 = new IPAddressString(o1.getRange());
                    IPAddressString range2 = new IPAddressString(o2.getRange());

                    if (range1.contains(range2)) {
                        return 1;
                    } else if (range2.contains(range1)) {
                        return -1;
                    } else if (range1.equals(range2)) {
                        return 0;
                    } else {
                        throw new RuntimeException(
                                "Cannot compare "
                                        + o1.getRange()
                                        + " and "
                                        + o2.getRange()
                                        + " as none contains the other.");
                    }
                });
        return ipRanges;
    }

    private Document createDocumentFromServerResult(ServerScanResult result) {
        Document document = new Document();
        document.put("result", result);
        return document;
    }
}
