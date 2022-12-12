/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.censor.constants.ConnectionPreset;
import java.util.List;

public class CensorScanDelegate {

    @Parameter(
            names = "-outputFolder",
            description = "Output folder for csv and pcap files of CensorScanner.")
    private String outputFolder = "/tmp/output";

    @Parameter(
            names = "-ipRangesFile",
            description = "Location of the file that contains IP ranges and AS information.")
    private String ipRangesFile = "ip_range_as_map.txt";

    @Parameter(
            names = "-connectionPresets",
            description = "List of connection presets that the scanner will consider.")
    private List<ConnectionPreset> connectionPresets =
            List.of(
                    ConnectionPreset.TLS12,
                    ConnectionPreset.RECORD_FRAG,
                    ConnectionPreset.TLS13,
                    ConnectionPreset.SNI,
                    ConnectionPreset.ESNI,
                    ConnectionPreset.ECH);

    public String getOutputFolder() {
        return outputFolder;
    }

    public List<ConnectionPreset> getConnectionPresets() {
        return connectionPresets;
    }

    public String getIpRangesFile() {
        return ipRangesFile;
    }
}
