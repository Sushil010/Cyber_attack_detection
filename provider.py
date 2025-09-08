import time
import argparse
from pathlib import Path
import pandas as pd

REQUIRED_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Min Packet Length",
    "Max Packet Length",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
]

EXTRA_COLS = ["Timestamp", "Label", "Destination Port", "Protocol"]

def simulate_stream(source_csv: Path, out_dir: Path, rows_per_file: int = 200, interval_sec: float = 1.0, include_extra: bool = True):
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(source_csv)
    df.columns = [c.strip() for c in df.columns]

    keep = [c for c in REQUIRED_COLS if c in df.columns]
    if include_extra:
        keep += [c for c in EXTRA_COLS if c in df.columns]
    if not keep:
        raise SystemExit(
            "None of the expected CICFlowMeter columns were found after stripping header spaces.\n"
            f"Expected any of: {REQUIRED_COLS}\n"
            f"Got: {list(df.columns)[:25]}... (showing first 25)"
        )

    df = df[keep]
    n = len(df)
    batch_id = 0
    print(f"[START] Streaming {n} rows from {source_csv} into {out_dir} in chunks of {rows_per_file} every {interval_sec}s.")
    while batch_id * rows_per_file < n:
        start = batch_id * rows_per_file
        end = min((batch_id + 1) * rows_per_file, n)
        chunk = df.iloc[start:end].copy()
        out_path = out_dir / f"flows_batch_{batch_id:06d}.csv"
        chunk.to_csv(out_path, index=False)
        print(f"[BATCH] Wrote rows {start}:{end} -> {out_path.name}")
        batch_id += 1
        time.sleep(interval_sec)
    print("[DONE] All rows streamed.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rows-per-file", type=int, default=200)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--no-extra", action="store_true")
    args = ap.parse_args()

    simulate_stream(
        Path(args.source),
        Path(args.out),
        rows_per_file=args.rows_per_file,
        interval_sec=args.interval,
        include_extra=(not args.no_extra),
    )

if __name__ == "__main__":
    main()
