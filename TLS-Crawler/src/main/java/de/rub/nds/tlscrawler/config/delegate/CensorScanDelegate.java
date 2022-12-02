/*
 * TLS-Crawler is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.censor.constants.ConnectionPreset;
import java.util.List;

public class CensorScanDelegate {

    @Parameter(names = "-outputFolder", description = "Output folder for csv and pcap files of CensorScanner.")
    private String outputFolder = "/tmp/output";

    @Parameter(names = "-connectionPresets", description = "List of connection presets that the scanner will consider.")
    private List<ConnectionPreset> connectionPresets =
        List.of(ConnectionPreset.TLS12, ConnectionPreset.RECORD_FRAG, ConnectionPreset.TLS13, ConnectionPreset.SNI, ConnectionPreset.ESNI, ConnectionPreset.ECH);

    public String getOutputFolder() {
        return outputFolder;
    }

    public List<ConnectionPreset> getConnectionPresets() {
        return connectionPresets;
    }
}
