import React, { useEffect, useRef, useState } from 'react';
import { api } from './api';

export default function StampDesigner({ onSaved }) {
  const fileInputRef = useRef(null);
  const canvasEl = useRef(null);
  const fabricRef = useRef(null);
  const [canvas, setCanvas] = useState(null);
  const [name, setName] = useState('My Designed Stamp');
  const [ready, setReady] = useState(false);
  const [imageLoading, setImageLoading] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState("");
  const openFilePicker = () => {
  fileInputRef.current?.click();
};

  useEffect(() => {
    let disposed = false;

    (async () => {
      try {
        const mod = await import('fabric');
        const fabric = mod.fabric || mod.default || mod;
        fabricRef.current = fabric;

        const c = new fabric.Canvas(canvasEl.current, {
          width: 400,
          height: 300,
          backgroundColor: 'rgba(255,255,255,0)',
        });

        if (!disposed) {
          setCanvas(c);
          setReady(true);
        }
      } catch (e) {
        console.error('Failed to load fabric:', e);
        alert('Failed to load designer. Try npm i fabric and refresh.');
      }
    })();

    return () => {
      disposed = true;
      if (canvas) canvas.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const ensure = () => {
    const fabric = fabricRef.current;
    if (!fabric || !canvas) {
      alert('Designer not ready yet.');
      return null;
    }
    return fabric;
  };

  const addText = () => {
    const fabric = ensure();
    if (!fabric) return;

    const t = new fabric.IText('Edit me', {
      left: 50,
      top: 50,
      fontSize: 24,
      fill: '#111827',
    });

    canvas.add(t);
    canvas.setActiveObject(t);
    canvas.renderAll();
  };

  const addCircle = () => {
    const fabric = ensure();
    if (!fabric) return;

    canvas.add(
      new fabric.Circle({
        left: 100,
        top: 90,
        radius: 80,
        stroke: '#2563eb',
        strokeWidth: 4,
        fill: 'rgba(0,0,0,0)',
      })
    );
    canvas.renderAll();
  };

  const addRect = () => {
    const fabric = ensure();
    if (!fabric) return;

    canvas.add(
      new fabric.Rect({
        left: 60,
        top: 60,
        width: 260,
        height: 180,
        stroke: '#ef4444',
        strokeWidth: 3,
        fill: 'rgba(0,0,0,0)',
      })
    );
    canvas.renderAll();
  };

  const addLogo = (e) => {
  const fabric = ensure();
  if (!fabric) return;

  const file = e.target.files?.[0];
  if (!file) return;

  //setSelectedFileName(file.name);
  //setImageLoading(true);
  setImageLoading(true);
  const failSafe = setTimeout(() => {
    setImageLoading(false);
  },   8000);

  const reader = new FileReader();

  reader.onload = async () => {
    try {
      const dataUrl = reader.result;
      if (!dataUrl) throw new Error("No image data returned");

      // Support newer and older fabric builds
      const fromURL =
        fabric.Image?.fromURL ||
        fabric.FabricImage?.fromURL;

      if (!fromURL) {
        throw new Error("Fabric image loader not available");
      }

      // Some fabric builds use callback style, some return a promise
      let img;

      if (fromURL.length >= 2) {
        img = await new Promise((resolve, reject) => {
          try {
            fromURL.call(
              fabric.Image || fabric.FabricImage,
              dataUrl,
              (loadedImg) => {
                if (!loadedImg) return reject(new Error("Failed to load image"));
                resolve(loadedImg);
              },
              { crossOrigin: null }
            );
          } catch (err) {
            reject(err);
          }
        });
      } else {
        img = await fromURL.call(
          fabric.Image || fabric.FabricImage,
          dataUrl,
          { crossOrigin: null }
        );
      }

      if (!img) throw new Error("Image could not be created");

      const maxW = canvas.getWidth() * 0.6;
      const maxH = canvas.getHeight() * 0.6;

      const imgW = img.width || 1;
      const imgH = img.height || 1;

      const scaleX = maxW / imgW;
      const scaleY = maxH / imgH;
      const scale = Math.min(scaleX, scaleY, 1);

      img.set({
        left: 50,
        top: 50,
        scaleX: scale,
        scaleY: scale,
        selectable: true,
        hasControls: true,
        hasBorders: true,
      });

      canvas.add(img);
      canvas.setActiveObject(img);
      canvas.renderAll();
    } catch (err) {
      console.error("Image load failed:", err);
      alert("Failed to load image into the designer.");
    } finally {
      const file = e.target.files?.[0];
      if (!file) return;

      setSelectedFileName(file.name);
      setImageLoading(true);

      clearTimeout(failSafe);
      setImageLoading(false);
    }
  };

  reader.onerror = () => {
    clearTimeout(failSafe);
    setImageLoading(false);
    alert("Could not read image file.");
  };

  reader.readAsDataURL(file);
  e.target.value = "";
};

  const exportPNG = async () => {
    const fabric = ensure();
    if (!fabric) return;

    const dataUrl = canvas.toDataURL({
      format: 'png',
      multiplier: 2,
      enableRetinaScaling: true,
    });

    const { saveAs } = await import('file-saver');
    saveAs(dataUrl, `${name}.png`);
  };

  const saveAsStamp = async () => {
    const fabric = ensure();
    if (!fabric) return;

    if (imageLoading) {
      alert('Please wait for the image to finish loading.');
      return;
    }

    canvas.discardActiveObject();
    canvas.renderAll();

    const multiplier = 2;
    const dataUrl = canvas.toDataURL({
      format: 'png',
      multiplier,
      enableRetinaScaling: true,
    });

    const res = await fetch(dataUrl);
    const blob = await res.blob();

    if (!blob || blob.size < 500) {
      alert('The stamp looks empty. Add text, shapes, or an image first.');
      return;
    }

    const password = prompt('Set a stamp password (used when applying this stamp)');
    if (!password) {
      alert('Password required');
      return;
    }

    const w = Math.round(canvas.getWidth() * multiplier);
    const h = Math.round(canvas.getHeight() * multiplier);

    const form = new FormData();
    form.append('image', new File([blob], `${name}.png`, { type: 'image/png' }));
    form.append('name', name);
    form.append('password', password);
    form.append('width', String(w));
    form.append('height', String(h));

    const r = await api.post('/stamps', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      withCredentials: true,
    });

    alert('Stamp saved!');

    if (typeof onSaved === 'function') {
      onSaved(r.data?.stamp);
    }
  };

  return (
    <div style={{ border: '1px solid #ddd', borderRadius: 8, padding: 16 }}>
      <h2>Stamp Designer</h2>

      <div style={{ marginBottom: 8 }}>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Stamp name"
        />
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={addLogo}
          style={{ display: "none" }}
        />

        <button
          type="button"
          onClick={openFilePicker}
          style={{ marginLeft: 8 }}
        >
          Choose Image
        </button>

        <span style={{ marginLeft: 8, color: "#555" }}>
          {selectedFileName || "No file chosen"}
        </span>

        <button onClick={addText} style={{ marginLeft: 8 }} disabled={!ready}>
          Add Text
        </button>
        <button onClick={addCircle} style={{ marginLeft: 8 }} disabled={!ready}>
          Add Circle
        </button>
        <button onClick={addRect} style={{ marginLeft: 8 }} disabled={!ready}>
          Add Rectangle
        </button>
      </div>

      <canvas
        ref={canvasEl}
        style={{ border: '1px dashed #bbb', background: 'transparent' }}
      />

      <div style={{ marginTop: 8 }}>
        <button onClick={exportPNG} disabled={!ready}>
          Download PNG
        </button>
        <button
          onClick={saveAsStamp}
          style={{ marginLeft: 8 }}
          disabled={!ready}
        >
          Save as Stamp
        </button>
      </div>

      {imageLoading && (
        <div style={{ marginTop: 8, color: '#555' }}>
          Loading image...
        </div>
      )}

      <small>
        Tip: click elements to move/resize; double-click text to edit.
      </small>
    </div>
  );
}
