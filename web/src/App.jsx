import React, { useState, useEffect } from "react";
import api from "./api";

export default function App() {
  const [file, setFile] = useState(null);
  const [bulkFiles, setBulkFiles] = useState([]);
  const [bulkDocumentIds, setBulkDocumentIds] = useState([]);
  const [bulkResults, setBulkResults] = useState([]);

  const [previewPdfFile, setPreviewPdfFile] = useState(null);
  const [previewLoaded, setPreviewLoaded] = useState(false);

  const [selectedStamp, setSelectedStamp] = useState("");
  const [stampPassword, setStampPassword] = useState("");

  const [stampX, setStampX] = useState(50);
  const [stampY, setStampY] = useState(50);
  const [stampScale, setStampScale] = useState(1);
  const [stampOpacity, setStampOpacity] = useState(1);

  const [err, setErr] = useState("");

  const clearErr = () => setErr("");
  const showErr = (e) => {
    console.error(e);
    setErr(e?.response?.data?.error || e.message);
  };

  // 👇 Auto preview bulk file
  useEffect(() => {
    if (!file && bulkFiles.length > 0) {
      setPreviewPdfFile(bulkFiles[0]);
      setPreviewLoaded(false);
    }
  }, [bulkFiles, file]);

  // ============================
  // BULK UPLOAD
  // ============================
  const uploadBulkPdfs = async () => {
    try {
      clearErr();
      const ids = [];

      for (const f of bulkFiles) {
        const fd = new FormData();
        fd.append("file", f);

        const r = await api.post("/documents/upload/documents", fd);
        const docId = r.data?.document?.id;

        if (docId) {
          ids.push({ id: docId, name: f.name });
        }
      }

      setBulkDocumentIds(ids);
      alert(`Uploaded ${ids.length} documents`);
    } catch (e) {
      showErr(e);
    }
  };

  // ============================
  // BULK APPLY
  // ============================
  const applyBulkStamp = async () => {
    try {
      clearErr();

      const r = await api.post(`/stamps/${selectedStamp}/apply-bulk`, {
        documentIds: bulkDocumentIds.map((d) => d.id),
        x: stampX,
        y: stampY,
        scale: stampScale,
        opacity: stampOpacity,
        password: stampPassword,
      });

      setBulkResults(r.data.results);
    } catch (e) {
      showErr(e);
    }
  };

  // ============================
  // BULK ZIP
  // ============================
  const downloadBulkZip = async () => {
    try {
      clearErr();

      const response = await api.post(
        `/stamps/${selectedStamp}/apply-bulk-zip`,
        {
          documentIds: bulkDocumentIds.map((d) => d.id),
          x: stampX,
          y: stampY,
          scale: stampScale,
          opacity: stampOpacity,
          password: stampPassword,
        },
        { responseType: "blob" }
      );

      const blob = new Blob([response.data], { type: "application/zip" });
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = "bulk-stamped.zip";
      a.click();

      window.URL.revokeObjectURL(url);
    } catch (e) {
      showErr(e);
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>eStamp Pro</h1>

      {/* ERROR */}
      {err && (
        <div style={{ color: "red", marginBottom: 10 }}>
          {err}
        </div>
      )}

      {/* PREVIEW */}
      <div style={{ marginBottom: 20 }}>
        <h2>Placement Preview</h2>
        <div style={{
          height: 400,
          border: "2px dashed red",
          position: "relative"
        }}>
          <div
            style={{
              position: "absolute",
              left: stampX,
              top: stampY,
              border: "2px dashed red",
              padding: 20
            }}
          >
            Stamp
          </div>
        </div>
      </div>

      {/* CONTROLS */}
      <div style={{ marginBottom: 20 }}>
        <input
          placeholder="Stamp ID"
          value={selectedStamp}
          onChange={(e) => setSelectedStamp(e.target.value)}
        />
        <input
          placeholder="Password"
          value={stampPassword}
          onChange={(e) => setStampPassword(e.target.value)}
        />

        <input
          type="number"
          value={stampX}
          onChange={(e) => setStampX(Number(e.target.value))}
        />
        <input
          type="number"
          value={stampY}
          onChange={(e) => setStampY(Number(e.target.value))}
        />
      </div>

      {/* BULK */}
      <div>
        <h2>Bulk Stamping</h2>

        <input
          type="file"
          multiple
          accept="application/pdf"
          onChange={(e) => {
            const files = Array.from(e.target.files || []);
            setBulkFiles(files);

            if (files.length) {
              setPreviewPdfFile(files[0]);
            }
          }}
        />

        <div style={{ marginTop: 10 }}>
          <button onClick={uploadBulkPdfs}>Upload</button>
          <button onClick={applyBulkStamp}>Apply</button>
          <button onClick={downloadBulkZip}>Download ZIP</button>
        </div>
      </div>

      {/* RESULTS */}
      <div style={{ marginTop: 20 }}>
        {bulkResults.map((r) => (
          <div key={r.documentId}>
            {r.filename} - {r.ok ? "OK" : "FAIL"}
          </div>
        ))}
      </div>
    </div>
  );
}