import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

function ScanHistoryTable({ scans, riskTrend, selectedScanUuid, onSelectScan }) {
  if (scans.length === 0) {
    return <p className="hint">No scans found for this application.</p>;
  }

  return (
    <div>
      {riskTrend.length > 1 && (
        <div className="chart-container">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={riskTrend}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" tick={{ fontSize: 12 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="risk_score"
                stroke="#2563eb"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Risk score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Commit</th>
              <th>Triggered At</th>
              <th>Trivy</th>
              <th>Dependency-Check</th>
              <th>SonarQube</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr
                key={scan.scan_uuid}
                className={scan.scan_uuid === selectedScanUuid ? "selected-row" : ""}
                onClick={() => onSelectScan(scan.scan_uuid)}
              >
                <td>{scan.commit_sha || scan.scan_uuid.slice(0, 8)}</td>
                <td>{new Date(scan.triggered_at).toLocaleString()}</td>
                <td>{scan.scanner_status?.trivy || "-"}</td>
                <td>{scan.scanner_status?.dependency_check || "-"}</td>
                <td>{scan.scanner_status?.sonarqube || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default ScanHistoryTable;
