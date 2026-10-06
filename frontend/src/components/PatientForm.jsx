import { useEffect, useState } from "react";

const EMPTY_PATIENT = {
  first_name: "",
  last_name: "",
  date_of_birth: "",
  gender: "",
  contact_number: "",
  email: "",
  address: "",
  medical_notes: "",
};

/**
 * Form used for both creating a new patient and editing an existing one.
 * Pass `initialData` to pre-fill the form for editing; omit it to create new.
 */
function PatientForm({ initialData, onSubmit, onCancel }) {
  const [formData, setFormData] = useState(initialData || EMPTY_PATIENT);
  const [submitError, setSubmitError] = useState(null);

  useEffect(() => {
    setFormData(initialData || EMPTY_PATIENT);
  }, [initialData]);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitError(null);
    try {
      await onSubmit(formData);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setSubmitError(
        typeof detail === "string"
          ? detail
          : "Could not save this patient record. Please check the fields and try again."
      );
    }
  };

  return (
    <form className="patient-form" onSubmit={handleSubmit}>
      <div className="form-grid">
        <label>
          First Name
          <input
            name="first_name"
            value={formData.first_name}
            onChange={handleChange}
            required
          />
        </label>

        <label>
          Last Name
          <input
            name="last_name"
            value={formData.last_name}
            onChange={handleChange}
            required
          />
        </label>

        <label>
          Date of Birth
          <input
            type="date"
            name="date_of_birth"
            value={formData.date_of_birth}
            onChange={handleChange}
            required
          />
        </label>

        <label>
          Gender
          <select name="gender" value={formData.gender || ""} onChange={handleChange}>
            <option value="">Select...</option>
            <option value="female">Female</option>
            <option value="male">Male</option>
            <option value="other">Other</option>
            <option value="prefer_not_to_say">Prefer not to say</option>
          </select>
        </label>

        <label>
          Contact Number
          <input
            name="contact_number"
            value={formData.contact_number || ""}
            onChange={handleChange}
          />
        </label>

        <label>
          Email
          <input
            type="email"
            name="email"
            value={formData.email || ""}
            onChange={handleChange}
          />
        </label>
      </div>

      <label>
        Address
        <textarea name="address" value={formData.address || ""} onChange={handleChange} />
      </label>

      <label>
        Medical Notes (synthetic data only)
        <textarea
          name="medical_notes"
          value={formData.medical_notes || ""}
          onChange={handleChange}
        />
      </label>

      {submitError && <p className="error">{submitError}</p>}

      <div className="form-actions">
        <button type="submit">Save</button>
        {onCancel && (
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

export default PatientForm;
