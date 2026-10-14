#!/usr/bin/env bash
# AI-LAB: sbatch train.sbatch   (log: train-<jobid>.out)
#SBATCH --job-name=ocpp-ae
#SBATCH --partition=l4
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=48G
#SBATCH --time=02:00:00
#SBATCH --output=train-%j.out
singularity exec --nv /ceph/container/pytorch/pytorch_26.09.sif \
    python3 train.py features/train.npz features/val.npz features/test.npz --out results/
