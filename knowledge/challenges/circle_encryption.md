# circle_encryption

## Challenge Info
- **Category**: Crypto
- **Difficulty**: 5
- **Flag**: `KoS{C4n_y0u_us3_b1n4ry_s34rch_t0_f1nd_7he_f14g?}`
- **Flag format**: `KoS{[a-zA-Z0-9_?!\.]+}`

## TL;DR
High-precision circle transform (81 iterations) with 12 masked output digits. Reverse via quartic polynomial root-finding (mpmath polyroots), beam search over masked digits scored by flag charset validity.

## Analysis

### Encryption
```python
R = RealField(4 * 116)  # 464-bit precision
x = R(flag_int * 10^(-116))
for r in range(20, 101):  # 81 iterations
    x = sqrt((r - 1/x)^2 - x^2)
ans = f'{x:f}'  # ~140 digit output
# 12 random positions replaced with '?'
```

### Key Properties
- Forward function is **monotonically increasing** (flag name is the hint)
- `RealField(464)` = ~139.7 significant decimal digits
- Output has ~140 chars → last ~20 digits may be precision noise
- 12 masked digits spread across positions 10-130

## Solution

### Step 1: Reverse via Quartic Roots
Given `x_new = sqrt((r - 1/u)^2 - u^2)`, squaring and rearranging:
`u^4 + (x_new^2 - r^2)*u^2 + 2r*u - 1 = 0`

For each step r=100→21: solve quartic, pick largest positive real root.
For r=20: pick root in [0.1, 1) range (flag * 10^(-116)).

mpmath `polyroots` with dps=220 works well for this.

### Step 2: Beam Search over Masked Digits
- 12 unknown output digits → beam search (width=5-10)
- For each digit candidate (0-9), reverse full chain → get flag candidate
- **Critical scoring**: count bytes matching flag charset `[a-zA-Z0-9_?!.]`
- Charset constraint eliminates wrong paths that look numerically close

### Step 3: Charset Constraint (The Key Insight)
- Flag format `KoS{[a-zA-Z0-9_?!\.]+}` restricts to 66 characters per byte
- Without this constraint: beam search converges to non-printable garbage
- With constraint: 44/44 valid bytes → unique solution in 12 beam steps
- **The flag format regex from challenge description is the most important constraint**

## Failed Approaches
1. **SageMath RealField(464) forward matching** — Sage version difference causes last ~20 output digits to differ → binary search converges to wrong value
2. **Binary search on flag integer** — converges to non-printable bytes (0x80, 0xce) because printable range is a tiny fraction of integer space
3. **Increasing precision (800, 1200, 2000 bits)** — doesn't help; problem is scoring, not precision
4. **Forward-only greedy search** — can't distinguish suffix bytes with RealField(464) (all give same match score)

## Key Lesson
**Always extract flag format regex from challenge description and use as solver constraint from the start.** This problem was solvable in 10 minutes with charset scoring but took hours without it.

## Files
- `solve.sage` — mpmath beam search solver with charset scoring
- `prob.sage` — original challenge source
- `output.txt` — encrypted output with 12 masked digits
