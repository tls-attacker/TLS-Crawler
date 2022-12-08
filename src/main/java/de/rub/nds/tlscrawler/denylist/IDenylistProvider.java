/*
 * TLS-Crawler is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2018-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.denylist;

import de.rub.nds.tlscrawler.data.ScanTarget;

public interface IDenylistProvider {

    boolean isDenylisted(ScanTarget target);
}
