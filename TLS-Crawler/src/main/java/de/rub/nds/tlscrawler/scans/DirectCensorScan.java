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
import de.rub.nds.censor.constants.ConnectionPreset;
import de.rub.nds.censor.execution.ServerScan;
import de.rub.nds.censor.execution.result.ServerScanResult;
import de.rub.nds.censor.network.AutonomousSystem;
import de.rub.nds.censor.network.IpAddress;
import de.rub.nds.censor.network.Ipv4Address;
import de.rub.nds.censor.network.ServerNetworkInformation;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
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
    private final String outputFolder;
    private final List<ConnectionPreset> connectionPresets;
    private final String ipRangeFile;

    private static final Logger LOGGER = LogManager.getLogger();

    public DirectCensorScan(
            ScanJob scanJob,
            long rabbitMqAckTag,
            RabbitMqOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            String outputFolder,
            List<ConnectionPreset> connectionPresets,
            String ipRangeFile) {
        super(scanJob, rabbitMqAckTag, orchestrationProvider, persistenceProvider);
        this.outputFolder = outputFolder;
        this.connectionPresets = connectionPresets;
        this.ipRangeFile = ipRangeFile;
    }

    @Override
    public void run() {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        CensorScannerConfig config = new CensorScannerConfig(generalDelegate);
        config.setConnectionPresets(connectionPresets);

        config.setOutputFolder(outputFolder);
        String ip = scanJob.getScanTarget().getIp();

        IpAddress chosenIp = new Ipv4Address(ip);
        ServerNetworkInformation serverNetworkInformation =
                new ServerNetworkInformation(
                        chosenIp, getAutonomousSystemListFromIp(ipRangeFile, ip), "unknown");

        ServerScan serverScan = new ServerScan(serverNetworkInformation, config);
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

    /**
     * Returns a list of autonomous systems for the given IP Address. Sorts the list by containment
     * of Ip address in different ranges and their size.
     *
     * @param ipRangeFile The file containing information about ipRanges and their Autonomous
     *     Systems
     * @param ip Ip Address to get autonomous systems for
     * @return List of {@link AutonomousSystem} sorted by their size
     */
    private List<AutonomousSystem> getAutonomousSystemListFromIp(String ipRangeFile, String ip) {

        List<AutonomousSystem> autonomousSystems = new LinkedList<>();
        List<String> ipRangesData;
        try (Stream<String> lines = Files.lines(Paths.get(ipRangeFile))) {
            ipRangesData = lines.collect(Collectors.toList());
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + ipRangeFile, ex);
        }

        for (String ipRangeData : ipRangesData) {
            String[] data = ipRangeData.split("\\|");
            String ipRange = data[0];
            String asNumber = data[1];
            String countryCode = data[2];
            String asName = data[3];

            if (new IPAddressString(ipRange).contains(new IPAddressString(ip))) {
                autonomousSystems.add(
                        new AutonomousSystem(
                                Integer.parseInt(asNumber), countryCode, asName, ipRange));
            }
        }

        autonomousSystems.sort(
                (o1, o2) -> {
                    IPAddressString range1 = new IPAddressString(o1.getIpRange());
                    IPAddressString range2 = new IPAddressString(o2.getIpRange());

                    if (range1.contains(range2)) {
                        return 1;
                    } else if (range2.contains(range1)) {
                        return -1;
                    } else if (range1.equals(range2)) {
                        return 0;
                    } else {
                        throw new RuntimeException(
                                "Cannot compare "
                                        + o1.getIpRange()
                                        + " and "
                                        + o2.getIpRange()
                                        + " as none contains the other.");
                    }
                });

        return autonomousSystems;
    }

    private Document createDocumentFromServerResult(ServerScanResult result) {
        Document document = new Document();
        document.put("result", result);
        return document;
    }
}
