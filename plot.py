import matplotlib.pyplot as plt   # 그래프 라이브러리
import statistics as st           # 평균, 표준편차

topos = ["line", "binary tree", "ring", "full mesh"]   # X축 순서

# ---- 여기에 측정값을 채우세요 (각 리스트 = 여러 번 측정한 값) ----
stp = {
    "line":        [126, 115, 123],
    "binary tree": [49, 45, 33],
    "ring":        [108, 112, 92],
    "full mesh":   [157, 153, 162],
}
rtt_us = {
    "line":        [1067, 976, 1062, 1023, 1008],
    "binary tree": [1028, 774, 954, 877, 853],
    "ring":        [772, 587, 598, 703, 626],
    "full mesh":   [194, 164, 242, 181, 318],
}

def bar(data, ylabel, title, fname):
    means = [st.mean(data[t]) for t in topos]                              # 막대 높이
    errs  = [st.stdev(data[t]) if len(data[t]) > 1 else 0 for t in topos]  # 오차 막대
    plt.figure(figsize=(6, 4))
    plt.bar(topos, means, yerr=errs, capsize=5)    # capsize: 오차 막대 끝 가로선
    plt.ylabel(ylabel)
    plt.xlabel("Topology")
    plt.title(title)
    plt.tight_layout()                             # 라벨 잘림 방지
    plt.savefig(fname, dpi=200)
    print(f"saved {fname}")

bar(stp,    "STP packets until convergence", "STP Convergence (8 nodes)", "stp_convergence.png")
bar(rtt_us, "Worst-case RTT (µs)",           "Worst-case RTT (8 nodes)",  "rtt.png")