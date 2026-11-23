"use client";

import { useState } from "react";
import { formatSize } from "@/lib/api";

export function FileDrop({ file, onFile, hint }: { file: File | null; onFile: (f: File) => void; hint?: string }) {
  const [over, setOver] = useState(false);
  return (
    <label
      className={`drop${over ? " over" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const f = e.dataTransfer.files?.[0];
        if (f) onFile(f);
      }}
    >
      <input
        type="file"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
      {file ? (
        <>
          <b>{file.name}</b> <span className="muted">({formatSize(file.size)}) — click to change</span>
        </>
      ) : (
        <>
          <b>Drop a file here</b> or click to choose
          <div className="muted small">{hint || "Image, document, video or dataset"}</div>
        </>
      )}
    </label>
  );
}
