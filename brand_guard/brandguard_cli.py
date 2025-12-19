from brand_guard.detectors import analyze_url
from brand_guard.scorer import score

def main():
    print("BrandGuard v0.1 — URL Risk Checker")

    while True:
        url = input("\nPaste a URL (or type 'q' to quit): ").strip()
        if url.lower() in ("q", "quit", "exit"):
            break

        result = analyze_url(url)
        if not isinstance(result, dict):
            print("ERROR: analyze_url returned:", result)
            continue
        risk, points = score(result.get("flags", []))

        print("\n--- Result ---")
        print("URL:    ", result["url"])
        print("Domain: ", result["domain"])

        if result["brand"]:
            print(
                "Brand:",
                result["brand"],
                "(official)" if result["official"] else "(NOT official)"
            )

            if "brand_score" in result:
                print(f"Brand confidence: {result['brand_score']}/100")
                if result.get("brand_reasons"):
                    print("Brand reasons:")
                    for r in result["brand_reasons"]:
                        print(" -", r)

        print("Risk:   ", risk.upper(), f"({points} pts)")
        print("Flags:")
        if result["flags"]:
            for f in result["flags"]:
                print(" -", f)
        else:
            print(" - none")

if __name__ == "__main__":
    main()