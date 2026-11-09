"""Regenerate the Bosphorus tables of the paper from the aggregate results.

Reads results/bosphorus_evasion.json (R-BOSPHORUS-20261109) and writes the
full supplementary table (bosphorus-full.tex) and the compact main-text table
of the arXiv version (bosphorus-compact.tex). No licensed data is needed.

Usage, from experiments/biometric:
  python -I scripts/make_bosphorus_tables.py [--results results/bosphorus_evasion.json] [--out-dir tables]
"""
import argparse, json, os

ap = argparse.ArgumentParser()
ap.add_argument("--results", default="results/bosphorus_evasion.json")
ap.add_argument("--out-dir", default="tables")
args = ap.parse_args()
os.makedirs(args.out_dir, exist_ok=True)
d = json.load(open(args.results, encoding="utf-8"))
T = d["tables"]
KEY = "openMissIncludingFailures"


def num(n):
    return f"{n:,}".replace(",", "{,}")


def cell(r):
    return r"%.1f\,[%.1f, %.1f]" % (100 * r["rate"], 100 * r["ci95"][0], 100 * r["ci95"][1])


def get(t, g):
    return T[t]["groups"][g]


def counts(g):
    v = get("FMR<=0.0001", g)
    return v[KEY]["n"], v["detectionFailures"]


def row(label, g, thr, full):
    n, f = counts(g)
    cells = " & ".join(cell(get(t, g)[KEY]) for t in thr)
    mid = f"{num(n)} & {f}" if full else f"{num(n)}"
    return f"{label} & {mid} & {cells} " + r"\\"


names = {"FMR<=0.001": r"$10^{-3}$", "FMR<=0.0001": r"$10^{-4}$", "FMR<=1e-05": r"$10^{-5}$", "FMR<=1e-06": r"$10^{-6}$"}
rows_att = [("Eyes occluded", "O_EYE"), ("Mouth occluded", "O_MOUTH"), ("Glasses", "O_GLASSES"), ("Hair occluded", "O_HAIR"),
            ("Six emotional expressions", "E_all"), ("Lower-face action units", "LFAU_all"),
            ("Upper-face action units", "UFAU_all"), ("Combined action units", "CAU_all"),
            (r"Yaw up to $30^\circ$", "YR_le30"), ("Slight pitch", "PR_slight")]
rows_oth = [(r"Yaw $45^\circ$", "YR_45"), (r"Yaw $90^\circ$", "YR_90"), ("Full pitch", "PR_full"), ("Diagonal turn", "CR_all")]

thr = ["FMR<=0.001", "FMR<=0.0001", "FMR<=1e-05", "FMR<=1e-06"]
L = [r"\begin{table*}[t]", r"\centering",
     r"\caption{Missed duplicates when 98 Bosphorus subjects re-enroll under changed appearance, in percent with 95\% Clopper--Pearson intervals (R-BOSPHORUS-20261109). Columns give the per-pair false match rate on which the LFW threshold was calibrated. An attempt without a detected face counts as missed, and $n$ includes these failures. The last row compares neutral images of one person against a gallery of the other 97 people and counts false duplicates.}",
     r"\label{tab:bosphorus}", r"\footnotesize", r"\setlength{\tabcolsep}{4pt}",
     r"\begin{tabular}{@{}>{\raggedright\arraybackslash}p{3.8cm}rrrrrr@{}}", r"\toprule",
     r"Condition & $n$ & Failed & " + " & ".join(names[t] for t in thr) + r" \\", r"\midrule",
     r"\multicolumn{7}{@{}l}{\textit{Conditions an attended station can accept}} \\"]
L += [row(a, g, thr, True) for a, g in rows_att]
L += [row("All of the above", "ATTENDED_pooled", thr, True), r"\addlinespace[2pt]",
      r"\multicolumn{7}{@{}l}{\textit{Conditions an attended station rejects}} \\"]
L += [row(a, g, thr, True) for a, g in rows_oth]
L += [r"\addlinespace[2pt]", r"\multicolumn{7}{@{}l}{\textit{Controls}} \\",
      row("Same person, neutral repeat", "N_repeat_control", thr, True)]
fd = " & ".join(cell(T[t]["falseDuplicateControl"]) for t in thr)
L += [f"False duplicates, 97-person gallery & {T[thr[0]]['falseDuplicateControl']['n']} & 0 & {fd} " + r"\\",
      r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
open(os.path.join(args.out_dir, "bosphorus-full.tex"), "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")

thr2 = ["FMR<=0.0001", "FMR<=1e-05"]
C = [r"\begin{table}[t]", r"\centering",
     r"\caption{Missed duplicates (\%, 95\% intervals) when 98 Bosphorus subjects re-enroll under changed appearance, at the thresholds calibrated on LFW for the per-pair false match rate in the header. A failed face detection counts as a miss. Supplementary Table~\ref{supp-tab:bosphorus} lists all conditions and thresholds.}",
     r"\label{tab:bosphorus-main}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
     r"\begin{tabular}{@{}>{\raggedright\arraybackslash}p{2.7cm}rrr@{}}", r"\toprule",
     r"Condition & $n$ & " + " & ".join(names[t] for t in thr2) + r" \\", r"\midrule"]
for a, g in [("Eyes occluded", "O_EYE"), ("Mouth occluded", "O_MOUTH"), ("Glasses", "O_GLASSES"), ("Hair occluded", "O_HAIR"),
             ("Six expressions", "E_all"), ("Lower-face action units", "LFAU_all"), (r"Yaw up to $30^\circ$", "YR_le30")]:
    C.append(row(a, g, thr2, False))
C += [row(r"\textbf{All attended conditions}", "ATTENDED_pooled", thr2, False), r"\addlinespace[2pt]",
      row(r"Yaw $90^\circ$", "YR_90", thr2, False), row("Same person, neutral", "N_repeat_control", thr2, False),
      r"\bottomrule", r"\end{tabular}", r"\end{table}"]
open(os.path.join(args.out_dir, "bosphorus-compact.tex"), "w", encoding="utf-8", newline="\n").write("\n".join(C) + "\n")
print("ok")
