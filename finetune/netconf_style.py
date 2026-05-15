"""
IEEE NetConfEval-style cumulative line plot generator for MIMIR evaluation.
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


RESULTS_PATH = Path("enhanced_results.json")
OUTPUT_STEM = Path("ieee_mimir_cumulative_accuracy")

MODEL_COLORS = {
    "base": "#F59E42",
    "finetuned": "#5CB85C",
}


plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 9,
    "font.weight": "bold",
    "axes.labelsize": 9,
    "axes.labelweight": "bold",
    "axes.titlesize": 9,
    "axes.titleweight": "bold",
    "axes.linewidth": 1.35,
    "axes.edgecolor": "#333333",
    "legend.fontsize": 8,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "figure.dpi": 150,
    "grid.linestyle": "--",
    "grid.alpha": 0.35,
    "grid.color": "#CCCCCC",
})


def load_results(path=RESULTS_PATH):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def collect_cumulative_series(results):
    base_values = np.asarray(
        [float(item["passed"]) for item in results["details"]["base"]],
        dtype=float,
    )
    ft_values = np.asarray(
        [float(item["passed"]) for item in results["details"]["finetuned"]],
        dtype=float,
    )

    if len(base_values) != len(ft_values):
        raise ValueError("Base and fine-tuned result counts do not match.")

    x = np.arange(1, len(base_values) + 1)
    return {
        "x": x,
        "base_curve": np.cumsum(base_values) / x,
        "ft_curve": np.cumsum(ft_values) / x,
    }


def sample_ticks(total):
    if total <= 60:
        return [tick for tick in [1, 10, 20, 30, 40, 50] if tick <= total]

    step = 25 if total <= 125 else 30
    ticks = [1] + list(range(step, total + 1, step))
    if ticks[-1] != total:
        ticks.append(total)
    return ticks


def draw_netconf_style_plot(results_path=RESULTS_PATH, output_stem=OUTPUT_STEM):
    results = load_results(results_path)
    series = collect_cumulative_series(results)
    x = series["x"]

    mark_every = max(1, len(x) // 8)
    fig, ax = plt.subplots(figsize=(3.45, 2.15))

    ax.plot(
        x,
        series["base_curve"],
        "--<",
        color=MODEL_COLORS["base"],
        linewidth=1.45,
        markersize=4.6,
        markerfacecolor="white",
        markeredgewidth=1.0,
        markevery=mark_every,
        label="Prompt-engineered",
        alpha=0.95,
    )
    ax.plot(
        x,
        series["ft_curve"],
        "-->",
        color=MODEL_COLORS["finetuned"],
        linewidth=1.45,
        markersize=4.6,
        markerfacecolor="white",
        markeredgewidth=1.0,
        markevery=mark_every,
        label="QLoRA fine-tuned",
        alpha=0.95,
    )

    ax.set_xlim(1, len(x))
    ax.set_ylim(-0.05, 1.05)
    ax.set_xticks(sample_ticks(len(x)))
    ax.set_yticks([0.00, 0.25, 0.50, 0.75, 1.00])
    ax.set_xlabel("Test sample index")
    ax.set_ylabel("Cumulative accuracy")
    ax.grid(True, which="major", linewidth=0.75)
    ax.set_axisbelow(True)
    for label in ax.get_xticklabels():
        label.set_fontweight("bold")
    for label in ax.get_yticklabels():
        label.set_fontweight("bold")
    ax.legend(
        loc="lower left",
        bbox_to_anchor=(0.03, 0.05),
        ncol=1,
        framealpha=0.92,
        edgecolor="gray",
        borderpad=0.35,
        handlelength=2.4,
        prop={"weight": "bold", "size": 8},
    )

    fig.tight_layout()
    fig.savefig(output_stem.with_suffix(".png"), dpi=300, bbox_inches="tight")
    fig.savefig(output_stem.with_suffix(".pdf"), bbox_inches="tight")

    print(f"Saved {output_stem.with_suffix('.png')}")
    print(f"Saved {output_stem.with_suffix('.pdf')}")
    print(
        "Overall strict: "
        f"{results['base_accuracy']:.1f}% -> {results['finetuned_accuracy']:.1f}% "
        f"({results['improvement_gap_pct']:+.1f} pp)"
    )
    print(
        "Overall weighted: "
        f"{results['base_weighted_accuracy']:.1f}% -> "
        f"{results['finetuned_weighted_accuracy']:.1f}% "
        f"({results['weighted_improvement_gap_pct']:+.1f} pp)"
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Draw a NetConfEval-style MIMIR evaluation plot.")
    parser.add_argument("--input", default=str(RESULTS_PATH), help="Input results JSON file.")
    parser.add_argument("--output", default=str(OUTPUT_STEM), help="Output path stem without extension.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    draw_netconf_style_plot(Path(args.input), Path(args.output))
