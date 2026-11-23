"""Train the optional learned detector and export it for the backend.

NOTE: this script has not been run on the machine the prototype was built on
(PyTorch could not be loaded there). Treat it as a starting point.

Dataset layout (any real-vs-synthetic image set, e.g. CIFAKE or GenImage):

    data/train/real/*.jpg   data/train/fake/*.jpg
    data/val/real/*.jpg     data/val/fake/*.jpg

Usage:
    pip install torch torchvision
    python ml/train_detector.py --data data --epochs 5

Writes models/detector.pt (TorchScript: 1x3x224x224 normalized tensor -> one
logit for P(fake)). The backend picks it up automatically on restart.
"""

import argparse
from pathlib import Path

import torch
from torch import nn
from torch.utils.data import DataLoader
from torchvision import datasets, models, transforms

MEAN, STD = [0.485, 0.456, 0.406], [0.229, 0.224, 0.225]


def loaders(root: Path, batch: int):
    train_tf = transforms.Compose([
        transforms.RandomResizedCrop(224, scale=(0.6, 1.0)),
        transforms.RandomHorizontalFlip(),
        transforms.ToTensor(),
        transforms.Normalize(MEAN, STD),
    ])
    # Must match TorchDetector.predict in app/analysis.py: plain resize to 224.
    val_tf = transforms.Compose([transforms.Resize((224, 224)), transforms.ToTensor(), transforms.Normalize(MEAN, STD)])
    train = datasets.ImageFolder(root / "train", train_tf)
    val = datasets.ImageFolder(root / "val", val_tf)
    assert train.class_to_idx == {"fake": 0, "real": 1}, f"expected fake/ and real/ folders, got {train.classes}"
    return DataLoader(train, batch, shuffle=True, num_workers=2), DataLoader(val, batch, num_workers=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "models" / "detector.pt")
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    train_dl, val_dl = loaders(args.data, args.batch)

    model = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
    model.fc = nn.Linear(model.fc.in_features, 1)
    model.to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    loss_fn = nn.BCEWithLogitsLoss()

    for epoch in range(args.epochs):
        model.train()
        for x, y in train_dl:
            # ImageFolder labels: fake=0, real=1 -> target 1.0 means fake.
            target = (y == 0).float().unsqueeze(1).to(device)
            opt.zero_grad()
            loss = loss_fn(model(x.to(device)), target)
            loss.backward()
            opt.step()

        model.eval()
        correct = total = 0
        with torch.no_grad():
            for x, y in val_dl:
                pred = (model(x.to(device)).squeeze(1) > 0).cpu()
                correct += (pred == (y == 0)).sum().item()
                total += len(y)
        print(f"epoch {epoch + 1}: val accuracy {correct / max(total, 1):.3f}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    model.cpu().eval()
    torch.jit.trace(model, torch.zeros(1, 3, 224, 224)).save(str(args.out))
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
