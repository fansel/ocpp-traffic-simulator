"""Per-message cross-evaluation: does the model flag foreign traffic in general, or only the attack messages?

Usage (AI-LAB container):
    python crosseval.py crosseval/a2 --train features/train.npz --val features/val.npz --model results/model.pt

Each request gets the error of its own position (max over all windows that contain it). The threshold is the
same 99.5th percentile of benign validation windows that train.py uses. Report: share of benign and of attack
requests above it, ROC-AUC between the two, and the most-flagged request types.
"""
import argparse
import collections

import numpy as np
import torch
from torch import nn

import features
from train import AutoEncoder, auc, errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--train", required=True)
    ap.add_argument("--val", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--quantile", type=float, default=99.5)
    args = ap.parse_args()
    device = "cuda" if torch.cuda.is_available() else "cpu"

    train, val = np.load(args.train, allow_pickle=True), np.load(args.val, allow_pickle=True)
    x = train["nums"]
    mean, std = x.mean((0, 1)), x.std((0, 1))           # same scaling as train.py
    for k in range(x.shape[2]):
        col = x[..., k][x[..., k] != 0]
        if len(col) < 0.5 * x[..., k].size:
            mean[k], std[k] = 0, col.std() if len(col) > 1 else 0
    std[std == 0] = 0.1
    vocab = list(train["vocab"])
    model = AutoEncoder(len(vocab), x.shape[2]).to(device)
    model.load_state_dict(torch.load(args.model, map_location=device))
    threshold = np.percentile(errors(model, torch.tensor(val["tokens"], dtype=torch.long),
                                     torch.tensor((val["nums"] - mean) / std), device), args.quantile)

    seqs, _ = features.extract(args.folder, train["registry"].item())
    index = {tok: k for k, tok in enumerate(vocab)}
    for cp, seq in seqs.items():
        tokens = torch.tensor([index.get(tok, 0) for tok, _, _ in seq], dtype=torch.long)
        nums = torch.tensor((np.array([n for _, n, _ in seq], np.float32) - mean) / std)
        score = np.zeros(len(seq))
        model.eval()
        with torch.no_grad():
            for k in range(0, len(seq) - features.WINDOW + 1, 4):   # windows with stride 4
                t, n = tokens[k:k + features.WINDOW][None].to(device), nums[k:k + features.WINDOW][None].to(device)
                logits, rec = model(t, n)
                ce = nn.functional.cross_entropy(logits.transpose(1, 2), t, reduction="none")
                err = (ce + ((rec - n) ** 2).sum(2))[0].cpu().numpy()
                score[k:k + features.WINDOW] = np.maximum(score[k:k + features.WINDOW], err)
        labels = np.array([lab for _, _, lab in seq])
        benign, flagged = labels == "benign", score > threshold
        print(f"{cp}: {len(seq)} requests, threshold {threshold:.1f}")
        print(f"  benign requests flagged: {flagged[benign].mean():.1%} of {benign.sum()}")
        print(f"  attack requests flagged: {flagged[~benign].mean():.1%} of {(~benign).sum()}")
        print(f"  ROC-AUC attack vs benign requests: {auc(score[benign], score[~benign]):.3f}")
        top = collections.Counter((seq[k][0], labels[k]) for k in np.where(flagged)[0]).most_common(8)
        print("  most flagged (request type, label):", top)
        unknown = sorted({tok for tok, _, _ in seq if tok not in index})
        print("  request types never seen in training:", unknown)


if __name__ == "__main__":
    main()
