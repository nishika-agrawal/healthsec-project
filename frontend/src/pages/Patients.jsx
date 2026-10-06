import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  createPatient,
  deletePatient,
  getPatients,
  logout,
  updatePatient,
} from "../api";
import PatientForm from "../components/PatientForm";
import NavBar from "../components/NavBar";

function Patients() {
  const [patients, setPatients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingPatient, setEditingPatient] = useState(null);
  const navigate = useNavigate();

  const loadPatients = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await getPatients();
      setPatients(data);
    } catch (err) {
      if (err?.response?.status === 401) {
        logout();
        navigate("/login");
        return;
      }
      setLoadError("Could not load patient records. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPatients();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCreate = async (formData) => {
    await createPatient(formData);
    setShowCreateForm(false);
    await loadPatients();
  };

  const handleUpdate = async (formData) => {
    await updatePatient(editingPatient.id, formData);
    setEditingPatient(null);
    await loadPatients();
  };

  const handleDelete = async (patientId) => {
    const confirmed = window.confirm("Delete this patient record? This cannot be undone.");
    if (!confirmed) return;
    await deletePatient(patientId);
    await loadPatients();
  };

  return (
    <div>
      <NavBar />
      <div className="page">
        <header className="page-header">
          <div>
            <h1>Patient Records</h1>
            <p className="hint">Synthetic demo data only - never enter real patient information.</p>
          </div>
        </header>

      {loadError && <p className="error">{loadError}</p>}

      {!showCreateForm && !editingPatient && (
        <button onClick={() => setShowCreateForm(true)}>+ Add Patient</button>
      )}

      {showCreateForm && (
        <section className="form-panel">
          <h2>New Patient</h2>
          <PatientForm onSubmit={handleCreate} onCancel={() => setShowCreateForm(false)} />
        </section>
      )}

      {editingPatient && (
        <section className="form-panel">
          <h2>Edit Patient</h2>
          <PatientForm
            initialData={editingPatient}
            onSubmit={handleUpdate}
            onCancel={() => setEditingPatient(null)}
          />
        </section>
      )}

      {loading ? (
        <p>Loading patient records...</p>
      ) : (
        <table className="patient-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Date of Birth</th>
              <th>Gender</th>
              <th>Contact</th>
              <th>Email</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {patients.map((patient) => (
              <tr key={patient.id}>
                <td>
                  {patient.first_name} {patient.last_name}
                </td>
                <td>{patient.date_of_birth}</td>
                <td>{patient.gender || "-"}</td>
                <td>{patient.contact_number || "-"}</td>
                <td>{patient.email || "-"}</td>
                <td className="actions-cell">
                  <button onClick={() => setEditingPatient(patient)}>Edit</button>
                  <button className="danger" onClick={() => handleDelete(patient.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {patients.length === 0 && (
              <tr>
                <td colSpan="6">No patient records yet. Click "Add Patient" to create one.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
      </div>
    </div>
  );
}

export default Patients;
