"""Benign-only anomaly detector: LSTM autoencoder over feature windows (from features.py).

Usage (on a GPU node):
    python train.py features/train.npz features/val.npz features/test.npz --out results/
    python train.py features/train.npz features/val.npz other_test.npz --model results/model.pt --out crosseval/

1. train : learn to reconstruct benign windows (token of each message + its numbers)
2. val   : anomaly score = largest reconstruction error of any single message in the window
            (attacks are local); threshold = 99.5th percentile of benign val scores
3. test  : flag windows above the threshold; report per attack type, per window and per attack event
            (an event = consecutive attack windows of one charger; detected if any of them is flagged)
"""
import argparse
import json
from pathlib import Path

import numpy as np
import torch
from torch import nn


class AutoEncoder(nn.Module):
    def __init__(self, vocab, n_nums, emb=16, hidden=64):
        super().__init__()
        self.embed = nn.Embedding(vocab, emb)
        self.encoder = nn.LSTM(emb + n_nums, hidden, batch_first=True)
        self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
        self.to_token, self.to_nums = nn.Linear(hidden, vocab), nn.Linear(hidden, n_nums)

    def forward(self, tokens, nums):
        _, (h, _) = self.encoder(torch.cat([self.embed(tokens), nums], -1))
        z = h[-1].unsqueeze(1).repeat(1, tokens.shape[1], 1)     # whole window squeezed into one vector
        out, _ = self.decoder(z)
        return self.to_token(out), self.to_nums(out)


def errors(model, tokens, nums, device, batch=2048):
    """Per-window score: max over messages of (token cross-entropy + summed squared error of its numbers)."""
    model.eval()
    scores = []
    with torch.no_grad():
        for k in range(0, len(tokens), batch):
            t, n = tokens[k:k + batch].to(device), nums[k:k + batch].to(device)
            logits, rec = model(t, n)
            ce = nn.functional.cross_entropy(logits.transpose(1, 2), t, reduction="none")   # per message
            scores.append((ce + ((rec - n) ** 2).sum(2)).max(1).values.cpu())
    return torch.cat(scores).numpy()


def auc(benign, attack):
    """Probability that a random attack window scores higher than a random benign one (ROC-AUC)."""
    ranks = np.argsort(np.argsort(np.concatenate([benign, attack]))) + 1
    return (ranks[len(benign):].sum() - len(attack) * (len(attack) + 1) / 2) / (len(benign) * len(attack))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("train")
    ap.add_argument("val")
    ap.add_argument("test")
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--quantile", type=float, default=99.5)
    ap.add_argument("--model", help="evaluate this trained model instead of training a new one")
    args = ap.parse_args()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(0)

    data = {name: np.load(path, allow_pickle=True) for name, path in [("train", args.train), ("val", args.val), ("test", args.test)]}
    x = data["train"]["nums"]
    mean, std = x.mean((0, 1)), x.std((0, 1))
    for k in range(x.shape[2]):
        col = x[..., k][x[..., k] != 0]
        if len(col) < 0.5 * x[..., k].size:              # sparse (meter, stop, flags): 0 stays 0, scale by non-zeros
            mean[k], std[k] = 0, col.std() if len(col) > 1 else 0
    std[std == 0] = 0.1                                   # a flag that never fires in benign traffic = 10 sigma
    tensors = {k: (torch.tensor(d["tokens"], dtype=torch.long), torch.tensor((d["nums"] - mean) / std))
               for k, d in data.items()}

    model = AutoEncoder(len(data["train"]["vocab"]), data["train"]["nums"].shape[2]).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    tokens, nums = tensors["train"]
    if args.model:
        model.load_state_dict(torch.load(args.model, map_location=device))
    for epoch in range(0 if args.model else args.epochs):
        model.train()
        perm, total = torch.randperm(len(tokens)), 0.0
        for k in range(0, len(tokens), 512):
            idx = perm[k:k + 512]
            t, n = tokens[idx].to(device), nums[idx].to(device)
            logits, rec = model(t, n)
            loss = nn.functional.cross_entropy(logits.transpose(1, 2), t) + nn.functional.mse_loss(rec, n)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        print(f"epoch {epoch + 1}: train loss {total / len(tokens):.4f}", flush=True)

    threshold = np.percentile(errors(model, *tensors["val"], device), args.quantile)
    scores, labels = errors(model, *tensors["test"], device), data["test"]["labels"]
    flagged, benign = scores > threshold, labels == "benign"
    report = {"threshold": float(threshold), "test_false_positive_rate": float(flagged[benign].mean()),
              "precision": float((flagged & ~benign).sum() / max(flagged.sum(), 1)), "per_attack": {}}
    for attack in sorted(set(labels) - {"benign"}):
        hit = labels == attack
        report["per_attack"][attack] = {"windows": int(hit.sum()), "recall": float(flagged[hit].mean()),
                                        "auc": float(auc(scores[benign], scores[hit])),
                                        "events": 0, "events_detected": 0}
    chargers, prev = data["test"]["chargers"], None
    for k, lab in enumerate(labels):                      # consecutive attack windows of one charger = 1 event
        if lab != "benign":
            if (chargers[k], lab) != prev:
                report["per_attack"][lab]["events"] += 1
                detected = False
            if flagged[k] and not detected:
                report["per_attack"][lab]["events_detected"] += 1
                detected = True
        prev = (chargers[k], lab) if lab != "benign" else None
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2))
    torch.save(model.state_dict(), args.out / "model.pt")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
