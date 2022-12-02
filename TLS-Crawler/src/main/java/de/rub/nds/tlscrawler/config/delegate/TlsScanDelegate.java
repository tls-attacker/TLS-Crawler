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
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlscrawler.config.ControllerCommandConfig;

public class TlsScanDelegate {

    @Parameter(names = "-scanDetail")
    private ScannerDetail scanDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-timeout", validateWith = ControllerCommandConfig.PositiveInteger.class, description = "The timeout to use inside the TLS-Scanner.")
    private int scannerTimeout = 2000;

    @Parameter(names = "-reexecutions", validateWith = ControllerCommandConfig.PositiveInteger.class, description = "Number of reexecutions to use in the TLS-Scanner.")
    private int reexecutions = 3;

    public ScannerDetail getScanDetail() {
        return scanDetail;
    }

    public int getScannerTimeout() {
        return scannerTimeout;
    }

    public int getReexecutions() {
        return reexecutions;
    }
}
