/**
 * Client-side report export: CSV (UTF-8 with BOM), Excel-compatible XML (.xls), JSON.
 * Excel uses SpreadsheetML (Excel 2003 XML); opens in Excel and LibreOffice without extra deps.
 */

export type ReportExportFormat = 'csv' | 'xls' | 'json';

export function csvEscapeCell(value: unknown): string {
  const s = value == null ? '' : String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function xmlEscapeCell(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function buildCsvContent(headers: string[], rows: string[][]): string {
  const headerLine = headers.map(csvEscapeCell).join(',');
  const dataLines = rows.map((row) => row.map(csvEscapeCell).join(','));
  return [headerLine, ...dataLines].join('\n');
}

/** Excel 2003 XML (SpreadsheetML); save as .xls */
export function buildExcelXmlContent(
  headers: string[],
  rows: string[][],
  sheetName: string
): string {
  const safeName = xmlEscapeCell(
    sheetName.slice(0, 31).replace(/[\[\]:*?/\\]/g, '_')
  );
  const headerRow = `<Row>${headers
    .map((h) => `<Cell><Data ss:Type="String">${xmlEscapeCell(h)}</Data></Cell>`)
    .join('')}</Row>`;
  const dataRows = rows
    .map(
      (r) =>
        `<Row>${r
          .map((c) => `<Cell><Data ss:Type="String">${xmlEscapeCell(c)}</Data></Cell>`)
          .join('')}</Row>`
    )
    .join('');
  return `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:html="http://www.w3.org/TR/REC-html40">
<Worksheet ss:Name="${safeName}">
<Table>
${headerRow}
${dataRows}
</Table>
</Worksheet>
</Workbook>`;
}

export function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export function rowsToPlainObjects(
  headers: string[],
  rows: string[][]
): Record<string, string>[] {
  return rows.map((r) =>
    Object.fromEntries(headers.map((h, i) => [h, r[i] ?? '']))
  );
}

export function downloadReport(
  filenameBase: string,
  format: ReportExportFormat,
  headers: string[],
  rows: string[][],
  sheetName: string,
  jsonData?: unknown
): void {
  const date = new Date().toISOString().split('T')[0];
  switch (format) {
    case 'csv': {
      const csv = '\ufeff' + buildCsvContent(headers, rows);
      triggerBlobDownload(
        new Blob([csv], { type: 'text/csv;charset=utf-8;' }),
        `${filenameBase}-${date}.csv`
      );
      break;
    }
    case 'xls': {
      const xml = buildExcelXmlContent(headers, rows, sheetName);
      triggerBlobDownload(
        new Blob([xml], { type: 'application/vnd.ms-excel;charset=utf-8;' }),
        `${filenameBase}-${date}.xls`
      );
      break;
    }
    case 'json': {
      const payload =
        jsonData !== undefined ? jsonData : rowsToPlainObjects(headers, rows);
      triggerBlobDownload(
        new Blob([JSON.stringify(payload, null, 2)], {
          type: 'application/json;charset=utf-8;'
        }),
        `${filenameBase}-${date}.json`
      );
      break;
    }
    default:
      break;
  }
}
