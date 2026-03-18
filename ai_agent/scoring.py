# ai_agent/scoring.py
# Final scoring logic prioritizing heuristics over reputation

def calculate_final_score(heuristic_score: int, reputation_score: int, url: str = "") -> int:
    """
    Balanced scoring: combines heuristic + reputation properly
    """

    # Base weighted score
    combined_score = (0.6 * reputation_score) + (0.4 * heuristic_score)

    # 🔥 High-risk TLD override (demo saver)
    if any(tld in url for tld in [".ru", ".xyz", ".tk"]):
        combined_score += 30

    return min(int(combined_score), 100)

