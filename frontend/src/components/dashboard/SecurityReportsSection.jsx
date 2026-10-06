import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const SEVERITY_COLORS = {
  CRITICAL: "#b91c1c",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
  UNKNOWN: "#6b7280",
};

function SecurityReportsSection({ features, findings }) {
  if (!features) return null;

  const severityData = [
    { severity: "Critical", count: features.critical_count, key: "CRITICAL" },
    { severity: "High", count: features.high_count, key: "HIGH" },
    { severity: "Medium", count: features.medium_count, key: "MEDIUM" },
    { severity: "Low", count: features.low_count, key: "LOW" },
  ];

  return (
    <section className="dashboard-section">
      <h2>Security Reports</h2>

      <div className="chart-container">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={severityData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
            <Tooltip />
            <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]}>
              {severityData.map((entry) => (
                <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {findings.length === 0 ? (
        <p className="hint">No findings for this scan.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Identifier</th>
                <th>Component / Package</th>
                <th>CVSS</th>
                <th>Fix Available</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <span
                      className="severity-dot"
                      style={{ backgroundColor: SEVERITY_COLORS[finding.normalized_severity] }}
                    />
                    {finding.normalized_severity}
                  </td>
                  <td>{finding.identifier || "-"}</td>
                  <td>{finding.component || finding.package_name || "-"}</td>
                  <td>{finding.cvss_score != null ? finding.cvss_score : "-"}</td>
                  <td>{finding.fix_available ? `Yes (${finding.fixed_version || "see report"})` : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default SecurityReportsSection;
