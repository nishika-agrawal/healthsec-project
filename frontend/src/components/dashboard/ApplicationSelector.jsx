function ApplicationSelector({ applications, selectedApplication, onSelect }) {
  if (applications.length === 0) {
    return (
      <p className="hint">
        No applications have been scanned yet. Submit a scan via the API (see{" "}
        <code>POST /scans</code> in the backend docs) to see data here.
      </p>
    );
  }

  return (
    <label className="application-selector">
      Application
      <select value={selectedApplication || ""} onChange={(e) => onSelect(e.target.value)}>
        {applications.map((app) => (
          <option key={app.id} value={app.name}>
            {app.name}
          </option>
        ))}
      </select>
    </label>
  );
}

export default ApplicationSelector;
