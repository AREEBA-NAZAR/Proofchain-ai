"""Download the pretrained detectors the backend uses (about 850 MB total).

    python ml/download_detector.py

Image model: Smogy/SMOGY-Ai-images-detector (Swin). License CC BY-NC 4.0:
             NON-COMMERCIAL USE ONLY. Replace it before any commercial use.
Text model:  Oxidane/tmr-ai-text-detector (RoBERTa, English). License MIT.

The backend runs without them (heuristics and safety checks only) and loads
them automatically on start when the files exist.
"""

import urllib.request
from pathlib import Path

MODELS = Path(__file__).resolve().parent.parent / "models"
HF = "https://huggingface.co"
FILES = {
    MODELS / "detector.onnx": f"{HF}/onnx-community/SMOGY-Ai-images-detector-ONNX/resolve/main/onnx/model.onnx",
    MODELS / "text-detector" / "tokenizer.json": f"{HF}/onnx-community/tmr-ai-text-detector-ONNX/resolve/main/tokenizer.json",
    MODELS / "text-detector" / "model.onnx": f"{HF}/onnx-community/tmr-ai-text-detector-ONNX/resolve/main/onnx/model.onnx",
}

for dest, url in FILES.items():
    if dest.is_file():
        print(f"have   {dest.relative_to(MODELS)}")
        continue
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"fetch  {dest.relative_to(MODELS)} ...")
    tmp = dest.with_suffix(dest.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)
    tmp.replace(dest)
print("done")
