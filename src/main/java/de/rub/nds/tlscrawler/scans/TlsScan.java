/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import com.mongodb.MongoClient;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlsscanner.ScanJob;
import de.rub.nds.tlsscanner.ThreadedScanJobExecutor;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.probe.ECPointFormatProbe;
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.probe.Tls13Probe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;
import org.bson.Document;
import static org.bson.codecs.configuration.CodecRegistries.fromProviders;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsScan implements IScan {

    private static Logger LOG = LoggerFactory.getLogger(TlsScan.class);

    private static String SCAN_NAME = "tls_scan";

    private final ParallelExecutor parallelExecutor;

    public TlsScan() {
        parallelExecutor = new ParallelExecutor(900, 4);
    }

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public Document scan(IScanTarget target) {
        LOG.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setScanDetail(ScannerDetail.NORMAL);
        config.setTimeout(1000);

        // TODO: Make port not hardcoded.
        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);
        List<TlsProbe> probeList = new LinkedList<>();
        probeList.add(new CommonBugProbe(config, parallelExecutor));
        probeList.add(new NamedCurvesProbe(config, parallelExecutor));
        probeList.add(new ProtocolVersionProbe(config, parallelExecutor));
        probeList.add(new CiphersuiteProbe(config, parallelExecutor));
        probeList.add(new ExtensionProbe(config, parallelExecutor));
        probeList.add(new Tls13Probe(config, parallelExecutor));
        probeList.add(new ECPointFormatProbe(config, parallelExecutor));
        probeList.add(new RenegotiationProbe(config, parallelExecutor));
        probeList.add(new InvalidCurveProbe(config, parallelExecutor));
        
        List<AfterProbe> afterList = new LinkedList<>();
        
        ScanJob scanJob = new ScanJob(probeList, afterList);
        ThreadedScanJobExecutor executor = new ThreadedScanJobExecutor(config, scanJob, parallelExecutor.getSize(), config
                            .getClientDelegate().getHost());
        
        
        TlsScanner scanner = new TlsScanner(config, executor, parallelExecutor, probeList, afterList);
        SiteReport report = scanner.scan();

        Document document = createDocumentFromSiteReport(report);

        return document;
    }

    Document createDocumentFromSiteReport(SiteReport report) {
        CodecRegistry pojoCodecRegistry = fromRegistries(MongoClient.getDefaultCodecRegistry(),
                fromProviders(PojoCodecProvider.builder().automatic(true).build()));
        Document document = new Document();
        document.put("report", report);
        return document;
    }
}
