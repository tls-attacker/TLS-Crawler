/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.config.delegate;

import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.censor.config.CensorScannerConfig;
import de.rub.nds.censor.constants.ConnectionPreset;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

public class CensorScanDelegate {

    @ParametersDelegate private final CensorScannerConfig censorScannerConfig;

    @Parameter(
            names = "-ipRangesFile",
            description = "Location of the file that contains IP ranges and AS information.")
    private String ipRangesFile = "ip_range_as_map.txt";

    public CensorScanDelegate() {
        this.censorScannerConfig = new CensorScannerConfig(new GeneralDelegate());
    }

    public String getIpRangesFile() {
        return ipRangesFile;
    }

    public CensorScannerConfig getCensorScannerConfig() {
        return censorScannerConfig;
    }
}
