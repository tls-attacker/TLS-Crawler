/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * A class generating IPs in configurable ranges.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class IpGenerator {
    private static Logger LOG = LoggerFactory.getLogger(IpGenerator.class);

    public static List<String> fullRange() {
        LOG.debug("fullRange() - Start.");
        List<String> result = new ArrayList<>();

        // This is obviously bull*
        // It serves as a testing device for now, will have to be replaced
        // Idea: Implement as a JavaRX source -- backpressured stream
        for (int a = 0; a < 256; a++) {
            //LOG.debug("fullRange() - Outermost Loop.");
            for (int b = 0; b < 256; b++) {
                for (int c = 0; c < 1; c++) {
                    for (int d = 0; d < 1; d++) {
                        result.add(String.format("%d.%d.%d.%d", a, b, c, d));
                    }
                }
            }
        }

        LOG.debug("fullRange() - Finish.");
        return result;
    }
}
