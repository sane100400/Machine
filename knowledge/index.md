# Machine — Knowledge Index

## Solved Challenges

| Challenge | Category | Technique | Flag |
|-----------|----------|-----------|------|
| [no_admin](challenges/no_admin.md) | web | cache poisoning / header smuggling / control-char stripping | DH{C4CH3_4DM1N_C4CH3_P0150N_C4CH3:ea+CF9NRZ0twnhtZ1y7P5w==} |
| [simple_login](challenges/simple_login.md) | web | JWT algorithm confusion (RS256→HS256) | DH{8ffb6790b2bb4248cc63b5e5cd04419109bc9ccd2b951c6e83638b0378c36854} |
| [jukebox](challenges/jukebox.md) | web | SSRF / php://filter / wrapwrap / filter_var bypass | DH{PHP_LF1_C4N_D0_4NYTH1NG:f1r6MddqQiJyfKOwVV0ZJg==} |
| [wasMazed](challenges/wasMazed.md) | rev | WebAssembly / Rust WASM / maze BFS / wasmtime dynamic analysis | DH{ddddddssddwwddddssaassddssddwwddwwwwddssssssaassaassaaaassddddssddddssaassdd} |
| [M](challenges/M.md) | rev | ELF relocation abuse / IFUNC BST branching / base-255+1 encoding / XTEA decoy | DH{f7c7c9f997bfb} |
| [Carillon](challenges/Carillon.md) | rev | RC4 / multi-process race / Union-Find constraint solving | DH{f5a139a7ad29de70da45df9a220448692190842605bb21829ad7417ea61a1cbb} |
| [run-for-flag](challenges/run-for-flag.md) | rev | algorithm optimization / convex hull / SHA256 | DH{783411f3bfb5c28862fb1bce4257b7f0d3ba91431f2d9e8dc7fbe42790b8ab55} |
| [stikcy](challenges/stikcy.md) | forensics | SQLite WAL recovery / Windows Sticky Notes / magic byte fix | KoS{W4L_WELL_STRUCTURED_4ND_T0UGH_S0_WE_NEED_4_BRE4K_} |
| [go_through_me](challenges/go_through_me.md) | web | CVE-2024-38475 LFI / /proc/self/mem XSS / chromedriver hijack / Composer RCE | DH{want_it?_go_through_me/FubWdrbGFkc21nbGFka25nbWFk} |
| [Mirage](challenges/Mirage.md) | rev | linear algebra / matrix equation / custom bignum (base-128 LE) | DH{fca5c7c52a86459f10ef963921a164d31c714328fd6de9f5fe} |
| [towa](challenges/towa.md) | crypto | ECC Pohlig-Hellman + BSGS / smooth-order curve / AES-ECB | KAPO{b34a3ac564560bdea87ac5c9044b93f2ce5e6a5996b32ddc63b247ee60ad588b} |
| PCG (learningdb) | crypto | LLL lattice reduction / polynomial PRNG / CVP embedding / AES-ECB | - |
| circle_encryption (learningdb) | crypto | high-precision Newton quartic reversal / beam search / SageMath | KoS{...} |
| SU_Forensics (SUCTF2026) | forensics | Windows disk multi-artifact / evtx / TabState / uTools / Ollama / CherryStudio | SUCTF{39e850db5d740c54df4281e39fb3866d} |
| SU_Artifact_Online (SUCTF2026) | misc | rune substitution / 5×5 cube command exec / PoW / constrained shell | SUCTF{Th1s_i5_@_Cub3_bu7_n0t_5ome7hing_u_pl4y} |
| SU_CyberTrack (SUCTF2026) | osint | blog→Minecraft→X/Twitter→Discord→email / identity chain / MD5 | SUCTF{c4d1df3b3dbea17c886b447b7f913048} |
| SU_MirrorBus9 (SUCTF2026) | misc | industrial bus / linear mod 65521 / 16-bit brute-force / session replay | SUCTF{mb9_file_only_flag_runtime_hardened} |

## Attempted / Failed

| Challenge | Category | Technique | Status |
|-----------|----------|-----------|--------|

## Techniques

### REV
- [rev_elf_relocation_chain](techniques/rev_elf_relocation_chain.md) — IFUNC abuse, relocation-based verification, XTEA decoy
- [rev_rc4_union_find](techniques/rev_rc4_union_find.md) — Cumulative RC4 KSA, Union-Find with parity XOR constraints
- [rev_matrix_linear_system](techniques/rev_matrix_linear_system.md) — Matrix equation over custom bignums, Gaussian elimination
- [rev_wasm_maze_bfs](techniques/rev_wasm_maze_bfs.md) — WASM runtime extraction + BFS maze solving
- [rev_convex_hull_hash](techniques/rev_convex_hull_hash.md) — Convex hull computation + SHA256 hash

### CRYPTO
- [crypto_lll_polynomial_pcg](techniques/crypto_lll_polynomial_pcg.md) — LLL/BKZ lattice reduction for polynomial PRNG recovery
- [crypto_ecc_pohlig_hellman](techniques/crypto_ecc_pohlig_hellman.md) — Pohlig-Hellman + BSGS on smooth-order ECC
- [crypto_circle_quartic_reversal](techniques/crypto_circle_quartic_reversal.md) — Newton's method quartic reversal + beam search

### WEB
- [web_cache_poisoning_header_smuggling](techniques/web_cache_poisoning_header_smuggling.md) — nginx control-char header smuggling cache poisoning
- [web_jwt_algorithm_confusion](techniques/web_jwt_algorithm_confusion.md) — JWT RS256→HS256 + RSA public key recovery from signatures
- [web_php_filter_chain_ssrf](techniques/web_php_filter_chain_ssrf.md) — PHP filter chain SSRF + wrapwrap JSON wrapper
- [web_apache_rewrite_lfi_xss_chain](techniques/web_apache_rewrite_lfi_xss_chain.md) — Apache %3F path truncation + LFI→XSS→CSRF chain
- [web_ctf_techniques](techniques/web_ctf_techniques.md) — General web CTF reference

### FORENSICS
- [forensics_sticky_notes_wal](techniques/forensics_sticky_notes_wal.md) — Windows Sticky Notes WAL magic byte fix
- [forensics_windows_disk_multiartifact](techniques/forensics_windows_disk_multiartifact.md) — Multi-artifact Windows disk forensics

### MISC / OSINT
- [misc_rune_cube_command_exec](techniques/misc_rune_cube_command_exec.md) — Rune substitution + 5×5 cube command execution
- [misc_industrial_bus_brute_force](techniques/misc_industrial_bus_brute_force.md) — Industrial bus protocol brute-force
- [osint_blog_identity_chain](techniques/osint_blog_identity_chain.md) — Cross-platform OSINT identity tracking

### PWN / Systems
- [heap_house_of_x](techniques/heap_house_of_x.md) — House of X heap exploitation
- [cpp_vtable_exploitation](techniques/cpp_vtable_exploitation.md) — C++ vtable exploitation
- [custom_allocator_exploitation](techniques/custom_allocator_exploitation.md) — Custom allocator exploitation
- [kernel_exploit_multistage](techniques/kernel_exploit_multistage.md) — Kernel multi-stage exploitation
- [gdb_oracle_reverse](techniques/gdb_oracle_reverse.md) — GDB oracle-based reversing

---

*Update this file after every challenge attempt.*
