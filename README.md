This is my course project for INSE 6120, presented at Concordia University by Dr. Jeremy Clark. 

In this project, I tried to use Noir (a Rust-based DSL designed by Aztec Labs) 
to address the existing issues in the Standard DMARC RUA reports, which list every sending IP, providing a "Target Map" for hackers. 
Considering the trade-offs, this might be a project worth exploring in the future, enabling private and verifiable computing in Web3 apps, 
by circuits hiding the IP and only outputting an Alignment Attestation, an attacker who intercepts the RUA report gains zero information 
about the organization's internal network topology or cloud provider landscape.

The system operates through three primary cryptographic layers built into the Noir circuit:

1. DMARC Alignment VerificationThe core logic enforces "Strict Alignment." It extracts the From: header and the DKIM d= (signing domain) tag. The circuit mathematically asserts that these two strings are identical. This ensures that the email is truly authorized by the domain it claims to be from, preventing spoofing at the protocol level.

2. Temporal Binning (Anti-Correlation)To prevent timing side-channel attacks, the system implements temporal binning. Instead of proving the exact Unix timestamp from the DKIM t= tag, the circuit "crushes" the time into a 4-hour window (bin).Logic: bin_id = timestamp / 14400Security Gain: Multiple emails arriving in the same window share the same bin_id, making it impossible for an attacker to correlate a specific report with their own server logs.

3. ZK-Threshold Reporting (Noise Reduction)To solve the "Crying Wolf" problem in network security, the system can be configured to only output a valid proof if a specific number of failures occur within a batch. This ensures that minor DNS glitches do not flood administrators with reports, while statistically significant attacks trigger a verified alert.


**System Architecture**
The system is divided into two main components:

The Rust Parser (/parser): * Acts as a pre-processor for the ZK circuit. Parses raw .eml files and performs "Relaxed" canonicalization. Extracts header indices (e.g., from_idx) and injects them into the circuit to reduce the computational cost of string searching in ZKP.

The Noir Circuit (/circuit): Verifies the 2048-bit RSA signature of the DKIM header.Executes the alignment and binning constraints.Outputs a constant-size (approx. 400 bytes) ZK-SNARK proof.Installation & Setup

Prerequisites

Rust: Install via rustup, also the Rust Analyzer extension in vscode

Nargo: The Noir build tool and package manager.

Barretenberg: The proving backend (usually installed automatically with Nargo).

Clone and Build

#### Clone the repository
```
git clone https://github.com/your-repo/zk-dmarc.git
cd zk-dmarc
```
#### Install Noir dependencies
```
cd circuit
nargo install
```

How to Run the System

Step 1: Prepare the Input. Place a raw email file (downloaded as "Original Source" from a provider like Gmail) into the root directory and name it test_email.eml. Ensure the email contains a valid DKIM-Signature header.

Step 2: Run the Rust ParserThe parser extracts the necessary cryptographic witnesses and prepares the Prover.toml for the Noir circuit.
```
cd parser
cargo run
```

Step 3: Generate the ZK Proof. Once the Prover.toml is generated in the circuit/ folder, use Nargo to generate the cryptographic proof.
```
cd ../circuit
nargo prove
```

Step 4: Verify the Proof. The proof can be verified by any third party (the domain owner or an auditor) without them ever seeing the original email.
```
nargo verify
```
Security & Evaluation Metrics
Metadata Entropy: The system reduces the "Information Surprise" of a report from full metadata (IP/Time/Subject) to a single policy attestation bit.

Proof Size: Regardless of the email size, the resulting proof remains a constant ~400 bytes, ensuring massive network efficiency for aggregate reporting.

Soundness: It is computationally infeasible for a malicious actor to forge a passing DMARC proof without possessing a validly signed DKIM header from the target domain.

Latency: Proving is performed asynchronously ($O(N \log N)$), ensuring zero impact on the critical path of email delivery.

**(The system still needs enhancements.)**
