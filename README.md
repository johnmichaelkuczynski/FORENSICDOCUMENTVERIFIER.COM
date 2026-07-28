# 🔬 Forensic Document Examiner

> **Upload a PDF. Describe what it claims to be. Get a court-ready forensic verdict in seconds.**

Whether you're verifying a lease agreement, a court order, a paycheck stub, or a government letter — the Forensic Document Examiner runs a multi-layer analysis and tells you exactly how well the document's internal evidence holds up against the claim.

---

## ✨ What It Does

Drop in any PDF and optionally tell the engine what the document *claims* to be — *"a federal court order signed by Judge Smith"*, *"a pay stub from Google HR"*, *"a notarized deed from 2018"*. Within seconds the engine cross-examines the file and returns a plain-language verdict.

No claim? No problem. Run it in **Exploration Mode** and get a complete catalogue of every metadata signal, software fingerprint, and structural property buried inside the file — without any judgment.

---

## 🏛️ The Five Verdicts

Every claim-based analysis ends with one of five verdicts:

| Verdict | What It Means |
|---|---|
| ✅ **Strong Match** | The document's internal evidence is consistent with the claim on all measurable dimensions |
| 🟡 **Partial Match** | Mostly consistent — but one or more signals deserve a second look |
| 🟠 **Weak Match** | Notable gaps or inconsistencies undermine the claim |
| 🔴 **Clearly Inconsistent** | Multiple independent signals directly contradict what the document claims to be |
| ⬜ **Inconclusive** | Not enough signal to form a judgment (exploration mode, password-protected files, etc.) |

---

## 🔍 What the Engine Examines

The examiner layers **structural heuristics** first, then sends the full dossier to an AI model for a synthesis verdict. Every finding is explicitly claim-relative — it answers *"does this support or undermine the specific claim?"*, with the claim text quoted inline.

### 📐 Technical Profile *(always present)*
Font count, embedding status, page count, PDF version, file size, AcroForm fields, JavaScript blocks, digital signature slots, linearization, object stream usage, XRef streams, encryption, and the number of incremental-save cycles — presented as neutral facts.

### 🖊️ Software Fingerprints
The PDF Author, Creator, and Producer metadata fields often name the exact application that made the file. A document claiming to be an official IRS notice but carrying `"Author: Dave, Creator: Microsoft Word 365"` is flagged immediately.

### 🕰️ Timestamp Conflicts
Creation and modification dates are checked against each other and against the claimed document date. A "1998 court record" produced by software that didn't exist until 2021 raises an immediate red flag.

### 💾 Incremental Save History
Every time a PDF is opened and re-saved, it appends a new section. The engine counts the exact number of these sections and flags documents that have been edited after their purported signing or issuance date.

### 📝 Template & Placeholder Text Detection
Unfinished fill-in-the-blank markers — `[INSERT NAME]`, `________`, `<Date>` — are caught and called out. Legitimate issued documents don't ship with unfilled fields.

### 🔤 Font & Metadata Consistency
Whether fonts are embedded, subsetted, or referenced-only is cross-referenced against what you'd expect from the claimed issuing authority and era.

---

## 💬 Ask the Document Anything

After the analysis, a **Chat panel** lets you interrogate the document directly. The AI has full access to every word of extracted text and every metadata field — ask it anything:

- *"What exact date does the signature line show?"*
- *"Does the body text mention a case number?"*
- *"Is there any contact information listed?"*

---

## 📄 Downloadable Evidence Report

Every completed analysis generates a formal **PDF Evidence Report** containing:

- 🔒 SHA-256 hash of the original file (tamper-evident provenance)
- The official verdict and match score
- Full AI-written summary
- Every finding, severity-coded and categorized
- Complete raw PDF metadata table

The report is self-contained and suitable for attaching to legal proceedings or internal investigations.

---

## 🗂️ Case History

The **Case History** page keeps a running record of every analysis you've run — with verdict breakdowns, file names, claimed identities, and timestamps. Re-run any previous case with one click if new context emerges.

---

## 🚀 Two Ways to Use It

### 🎯 Claim Mode *(default)*
Provide a description of what the document purports to be. Every finding is written in terms of whether it supports or undermines that specific claim.

### 🔭 Exploration Mode
Leave the claim field blank. The engine catalogues everything it finds — software history, creation chain, structural anomalies, metadata fields — without rendering a judgment. Ideal for an initial survey before you know what you're looking for.

---

## 🛡️ Designed For

- 🏛️ **Legal professionals** verifying documents submitted as evidence
- 🏢 **HR and compliance teams** authenticating submitted credentials
- 🏦 **Financial institutions** reviewing income and asset documentation
- 🔎 **Investigators and journalists** vetting source materials
- 👤 **Individuals** who want to know if a document they received is genuine

---

*The Forensic Document Examiner surfaces structural and metadata signals — it is a decision-support tool, not a substitute for professional legal or forensic opinion.*
