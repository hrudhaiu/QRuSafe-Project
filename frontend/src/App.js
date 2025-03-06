import React, { useState, useEffect, useRef } from "react";
import { Html5QrcodeScanner } from "html5-qrcode";
import axios from "axios";
import "./App.css";

function App() {
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const scannerRef = useRef(null);
  const readerRef = useRef(null);

  useEffect(() => {
    if (scanning && readerRef.current) {
      const config = { fps: 10, qrbox: 250 };
      const verbose = false;
      const html5QrcodeScanner = new Html5QrcodeScanner("reader", config, verbose);
      html5QrcodeScanner.render(onScanSuccess, onScanFailure);
      scannerRef.current = html5QrcodeScanner;
    }
  }, [scanning]);

  const startScanner = () => {
    setScanning(true);
  };

  const onScanSuccess = (decodedText) => {
    if (scannerRef.current) {
      scannerRef.current.clear()
        .then(() => console.log("Scanner stopped after successful scan"))
        .catch((error) => console.error("Failed to stop scanner:", error));
    }
    setScanning(false);
    checkUrlSafety(decodedText);
  };

  const onScanFailure = (error) => {
    console.warn(`QR Code scan error: ${error}`);
  };

  const checkUrlSafety = async (url) => {
    setLoading(true);
    setResult(null);
    setShowDetails(false);

    try {
      const response = await axios.post("http://localhost:5001/api/check-url", { url }, {
        headers: { "Content-Type": "application/json" }
      });
      console.log("Backend Response:", response.data);
      setResult({ ...response.data, url });
    } catch (error) {
      console.error("Error checking URL safety:", error);
      setResult({ safe: false, details: "Error occurred while checking URL." });
    }

    setLoading(false);
  };

  return (
    <div className="App">
      <h1>QR Code Safety Checker</h1>

      {scanning ? (
        <>
          <div ref={readerRef} id="reader"></div>
          <button onClick={() => setScanning(false)}>Stop Scanner</button>
        </>
      ) : (
        <button onClick={startScanner}>Start QR Code Scanner</button>
      )}

      {loading && (
        <div className="loading">
          <p>Scanning in progress...</p>
        </div>
      )}

      {!loading && result && (
        <div className={`result ${result.safe === true ? "safe" : "danger"}`}>
          <h2>Scan Result:</h2>

          {result.safe ? (
            <>
              <p>✅ Safe Link</p>
              <p>This link appears to be safe.</p>
              <a href={result.url} target="_blank" rel="noopener noreferrer">
                Open Scanned Link
              </a>
            </>
          ) : (
            <>
              <p>⚠️ Potentially Dangerous!</p>
              <p>This link might be harmful. Proceed with caution.</p>
              
              {/* Summary of Overall Threat */}
              {result.details && result.details.virustotal && result.details.virustotal.length > 0 && (
                <div className="threat-summary">
                  <p><strong>Overall Category:</strong> {result.details.virustotal[0].category}</p>
                  <p><strong>Overall Reason:</strong> {result.details.virustotal[0].reason}</p>
                  <button onClick={() => setShowDetails(!showDetails)}>
                    {showDetails ? "Hide Details" : "View More Info"}
                  </button>
                </div>
              )}

              {/* Full Threat Details */}
              {showDetails && result.details && (
                <div className="threat-box">
                  <h3>VirusTotal Threats:</h3>
                  {result.details.virustotal.map((match, index) => (
                    <div key={index}>
                      <p><strong>Detected by:</strong> {match.engine}</p>
                      <p><strong>Category:</strong> {match.category}</p>
                      <p><strong>Reason:</strong> {match.reason}</p>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;