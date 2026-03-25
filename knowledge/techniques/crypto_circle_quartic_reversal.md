# High-Precision Circle Encryption Reversal (circle_encryption)

## Category
CRYPTO — numerical methods, high-precision arithmetic

## Technique
Forward encryption applies 81 iterations of a "circle" transform: x_new = sqrt((r - 1/x_old)² - x_old²) for r = 20..100. Output has 12 missing digits. Recover original input (flag as integer × 10^(-116)) by reversing all iterations using Newton's method on the quartic equation.

### Reversal
Given x_new and r, find x_old by solving quartic: u⁴ + (x_new² - r²)·u² + 2r·u - 1 = 0
- Initial guess: u ≈ √(r² - x_new²) (from geometric approximation)
- Newton's method: 200 iterations with convergence check at 2^(-PREC+10)
- Multiple starting points as fallback: [0.5, 0.1, 2.0, 5.0, 10.0, 0.01, 1/r + 0.001]
- Verify solution: |√((r - 1/u)² - u²) - x_new| < 10^(-100)

### Missing Digit Recovery
- 12 missing digits → 10^12 brute-force infeasible
- Beam search (width=5-10): process each missing position left-to-right
- For each digit candidate: fill remaining unknowns, do full reversal
- **CRITICAL: Score by flag charset validity, NOT residual**
  - Count bytes matching flag regex charset (e.g., `[a-zA-Z0-9_?!.]`)
  - Full regex match = +1000 bonus
  - Residual-only scoring leads to wrong paths (non-printable bytes can have lower residual)

### Key Patterns
- mpmath `polyroots` (dps=220) works better than SageMath polynomial roots for this
- Sage version differences cause `f'{x:f}'` output to differ in last ~20 digits → forward matching unreliable
- **Flag format regex from challenge description is the #1 constraint** — apply to scoring immediately
- Beam search + charset scoring converges in 12 steps (~120 forward evaluations)
- Without charset constraint: hours of wasted precision tuning. With it: 10 minutes.

## Tools
- mpmath (polyroots for quartic, high dps for reversal precision)
- Python (beam search, charset scoring)
- Challenge description parsing (flag format regex extraction)
