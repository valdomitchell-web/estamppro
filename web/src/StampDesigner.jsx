import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';

export default function StampDesigner({ API, authHeader }) {
  const canvasEl = useRef(null);
  const fabricRef = useRef(null);  // holds the loaded fabric module
  const [canvas, setCanvas] = useState(null);
  const [name, setName] = useState('My Designed Stamp');
  const [ready, setReady] = useState(false);

  // Lazy-load fabric at runtime to avoid module resolution issues
  useEffect(() => {
    let disposed = false;
    (async () => {
      try {
        const mod = await import('fabric');            // ESM
        const fabric = mod.fabric || mod.default || mod; // handle various exports
        fabricRef.current = fabric;
        const c = new fabric.Canvas(canvasEl.current, {
          width: 400, height: 300, backgroundColor: 'rgba(255,255,255,0)'
        });
        c.add(new fabric.Text('Your Text', { left:120, top:130, fontSize:28, fill:'#1f2937' }));
        if (!disposed) { setCanvas(c); setReady(true); }
      } catch (e) {
        console.error('Failed to load fabric:', e);
        alert('Failed to load designer. Try npm i fabric and refresh.');
      }
    })();
    return () => { disposed = true; if (canvas) canvas.dispose(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const ensure = () => {
    const fabric = fabricRef.current;
    if (!fabric || !canvas) { alert('Designer not ready yet.'); return null; }
    return fabric;
  };

  const addText = () => {
    const fabric = ensure(); if (!fabric) return;
    const t = new fabric.IText('Edit me', { left:50, top:50, fontSize:24, fill:'#111827' });
    canvas.add(t).setActiveObject(t); canvas.renderAll();
  };

  const addCircle = () => {
    const fabric = ensure(); if (!fabric) return;
    canvas.add(new fabric.Circle({ left:100, top:90, radius:80, stroke:'#2563eb', strokeWidth:4, fill:'rgba(0,0,0,0)' }));
  };

  const addRect = () => {
    const fabric = ensure(); if (!fabric) return;
    canvas.add(new fabric.Rect({ left:60, top:60, width:260, height:180, stroke:'#ef4444', strokeWidth:3, fill:'rgba(0,0,0,0)' }));
  };

  const addLogo = (e) => {
    const fabric = ensure(); if (!fabric) return;
    const f = e.target.files?.[0]; if (!f) return;
    const url = URL.createObjectURL(f);
    fabric.Image.fromURL(url, img => {
      img.set({ left:160, top:90, scaleX:0.5, scaleY:0.5 });
      canvas.add(img); canvas.renderAll(); URL.revokeObjectURL(url);
    }, { crossOrigin: 'anonymous' });
  };

  const exportPNG = async () => {
    const fabric = ensure(); if (!fabric) return;
    const dataUrl = canvas.toDataURL({ format:'png', multiplier:2, enableRetinaScaling:true });
    const { saveAs } = await import('file-saver');
    saveAs(dataUrl, `${name}.png`);
  };

  const saveAsStamp = async () => {
    const fabric = ensure(); if (!fabric) return;
    const dataUrl = canvas.toDataURL({ format:'png', multiplier:2, enableRetinaScaling:true });
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    const password = prompt('Set a stamp password (used when applying this stamp)');
    if (!password) return alert('Password required');
    const form = new FormData();
    form.append('image', new File([blob], `${name}.png`, { type:'image/png' }));
    form.append('name', name);
    form.append('password', password);
    await axios.post(`${API}/stamps`, form, { headers: { ...authHeader(), 'Content-Type':'multipart/form-data' } });
    alert('Stamp saved!');
  };

  return (
    <div style={{ border:'1px solid #ddd', borderRadius:8, padding:16 }}>
      <h2>Stamp Designer</h2>
      <div style={{marginBottom:8}}>
        <input value={name} onChange={e=>setName(e.target.value)} placeholder="Stamp name" />
        <input type="file" accept="image/*" onChange={addLogo} style={{marginLeft:8}} />
        <button onClick={addText}  style={{marginLeft:8}} disabled={!ready}>Add Text</button>
        <button onClick={addCircle} style={{marginLeft:8}} disabled={!ready}>Add Circle</button>
        <button onClick={addRect}  style={{marginLeft:8}} disabled={!ready}>Add Rectangle</button>
      </div>
      <canvas ref={canvasEl} style={{ border:'1px dashed #bbb', background:'transparent' }} />
      <div style={{marginTop:8}}>
        <button onClick={exportPNG}  disabled={!ready}>Download PNG</button>
        <button onClick={saveAsStamp} style={{marginLeft:8}} disabled={!ready}>Save as Stamp</button>
      </div>
      <small>Tip: click elements to move/resize; double-click text to edit.</small>
    </div>
  );
}
