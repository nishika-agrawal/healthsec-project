const DECISION_LABELS = {
  approved: "Approved",
  review_required: "Review Required",
  blocked: "Blocked",
};

const DECISION_CLASS = {
  approved: "badge badge-approved",
  review_required: "badge badge-review",
  blocked: "badge badge-blocked",
};

function DeploymentHistoryTable({ history }) {
  return (
    <section className="dashboard-section">
      <h2>Deployment History</h2>

      {history.length === 0 ? (
        <p className="hint">No deployment decisions recorded yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Version (Commit)</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Decided At</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item, index) => (
                <tr key={index}>
                  <td>{item.application_name || "-"}</td>
                  <td>{item.commit_sha || item.scan_uuid?.slice(0, 8) || "-"}</td>
                  <td>{item.risk_category || "-"}</td>
                  <td>
                    <span className={DECISION_CLASS[item.decision] || "badge"}>
                      {DECISION_LABELS[item.decision] || item.decision}
                    </span>
                  </td>
                  <td className="reason-cell">{item.reason}</td>
                  <td>{new Date(item.decided_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default DeploymentHistoryTable;
