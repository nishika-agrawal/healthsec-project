function LoadingSpinner({ label = "Loading..." }) {
  return (
    <div className="loading-state" role="status">
      <div className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export default LoadingSpinner;
