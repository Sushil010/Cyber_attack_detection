import argparse, glob, shutil, time, hashlib, requests
from pathlib import Path
import pandas as pd

FEATURE_ORDER = [
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

def stable_coord(seed: str):
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    a = int(h[:16], 16) / 2**64
    b = int(h[16:32], 16) / 2**64
    return (a * 180.0 - 90.0, b * 360.0 - 180.0)

def push_to_ui(rows, url="http://localhost:8000/ingest"):
    payload = []
    for r in rows:
        seed = f"{r.get('Flow Duration','')}{r.get('Total Fwd Packets','')}{r.get('Total Backward Packets','')}"
        srcLat, srcLng = stable_coord("SRC"+seed)
        dstLat, dstLng = stable_coord("DST"+seed)
        label = str(r.get("prediction", r.get("Label", "BENIGN")))
        try:
            score = float(r.get("score", 1.0 if label != "BENIGN" else 0.2))
        except Exception:
            score = 0.5
        payload.append({"srcLat": srcLat, "srcLng": srcLng, "dstLat": dstLat, "dstLng": dstLng, "label": label, "score": score})
    try:
        requests.post(url, json=payload, timeout=1.5)
    except Exception as e:
        print(f"[WARN] UI push failed: {e}")

def safe_select(df: pd.DataFrame, cols):
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    present = [c for c in cols if c in df.columns]
    if len(present) < len(cols):
        missing = [c for c in cols if c not in df.columns]
        print(f"[WARN] missing columns: {missing}")
    return df[present].copy(), df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_dir", required=True)
    ap.add_argument("--processed", default=None)
    ap.add_argument("--sleep", type=float, default=0.5)
    ap.add_argument("--predict", default=None)
    ap.add_argument("--out-csv", default="predictions.csv")
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    in_dir.mkdir(parents=True, exist_ok=True)
    processed = Path(args.processed) if args.processed else in_dir / "processed"
    processed.mkdir(parents=True, exist_ok=True)

    pipe = None
    if args.predict:
        try:
            import joblib
            pipe = joblib.load(args.predict)
            print(f"[OK] loaded pipeline: {args.predict}")
        except Exception as e:
            print(f"[ERROR] could not load pipeline: {e}")

    seen = set()
    print(f"[START] watching {in_dir} (poll {args.sleep}s). CTRL+C to stop.")
    try:
        while True:
            files = sorted(glob.glob(str(in_dir / "flows_batch_*.csv")))
            for fp in files:
                if fp in seen:
                    continue
                try:
                    df_raw = pd.read_csv(fp)
                except Exception:
                    continue

                X, df_all = safe_select(df_raw, FEATURE_ORDER)

                if pipe is not None and not X.empty:
                    try:
                        yhat = pipe.predict(X)
                        out = df_all.copy()
                        out["prediction"] = yhat
                        header = not Path(args.out_csv).exists()
                        out.to_csv(args.out_csv, mode="a", index=False, header=header)
                        push_to_ui(out.to_dict(orient="records"))
                        print(f"[PRED] {Path(fp).name}: {len(out)} rows -> {args.out_csv} + UI")
                    except Exception as e:
                        print(f"[ERROR] predict failed for {fp}: {e}")
                else:
                    push_to_ui(df_all.to_dict(orient="records"))
                    print(f"[BATCH] {Path(fp).name}: {len(df_all)} rows (no model) -> UI")

                seen.add(fp)
                try:
                    shutil.move(fp, processed / Path(fp).name)
                except Exception as e:
                    print(f"[WARN] could not move {fp}: {e}")

            time.sleep(args.sleep)
    except KeyboardInterrupt:
        print("\n[STOP] exiting.")

if __name__ == "__main__":
    main()
