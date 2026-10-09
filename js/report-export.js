(function () {
  function buildReportData(reportContext) {
    const { analystLabel, investigations, iocs, events, summary, scope, filters } = reportContext;
    return {
      reportId: `RPT-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      analyst: analystLabel || 'Analyst-01',
      iocDetails: iocs || [],
      riskScoreSummary: summary || {},
      investigationHistory: investigations || [],
      relatedEvents: events || [],
      scope: scope || `Browser-local saved events (${(events || []).length})`,
      appliedFilters: filters || {},
      dataSource: 'Browser-local saved records; no live source connection',
      confidence: 'Local record confidence only. External threat intelligence is not queried or independently verified.'
    };
  }

  function downloadBlob(filename, data, type) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function toCsv(rows) {
    if (!rows.length) return 'No data\n';
    const headers = Object.keys(rows[0]);
    const csv = [headers.join(',')];
    rows.forEach((row) => {
      csv.push(headers.map((header) => Validation.csvEscape(row[header] ?? '')).join(','));
    });
    return csv.join('\n');
  }

  function exportJsonReport(context) {
    const report = buildReportData(context);
    const text = JSON.stringify(report, null, 2);
    const filename = `threatscope-report-${report.reportId}.json`;
    downloadBlob(filename, text, 'application/json');
    return report;
  }

  function exportCsvReport(rows, prefix = 'threatscope-export') {
    const csv = toCsv(rows);
    const filename = `${prefix}-${Date.now()}.csv`;
    downloadBlob(filename, csv, 'text/csv;charset=utf-8;');
    return csv;
  }

  window.ReportExport = {
    buildReportData,
    exportJsonReport,
    exportCsvReport,
    toCsv
  };
})();
