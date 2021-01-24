/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanTarget;
import org.bson.Document;

/**
 * Interface to be implemented by scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScan {

    /**
     * @return A unique name.
     */
    String getName();

    /**
     * @param target Target of the scan.
     * @return The scan's result in a Bson Document.
     */
    Document scan(ScanTarget target);

}
