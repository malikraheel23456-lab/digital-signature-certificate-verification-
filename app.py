import streamlit as st
import pandas as pd
from datetime import datetime

from crypto_utils import generate_key_pair, sign_document, verify_signature, evaluate_trust
from database import init_db, add_activity, get_activities, clear_activities
from reports import create_verification_pdf

st.set_page_config(page_title="Digital Signature & Certificate Verification", page_icon="🔐", layout="wide")
init_db()

st.title("🔐 Digital Signature & Certificate Verification System")
st.caption("Academic prototype | RSA-PSS + SHA-256 | Simulated classroom trust directory")

with st.expander("About this project and its limits"):
    st.write("This application demonstrates document signing, signature verification, tamper detection, "
             "and matching a public key to a simulated trusted-key record. The record is an educational "
             "trust model, not a real X.509 certificate or a production certificate authority.")

# Main navigation
page = st.sidebar.radio("Navigation", ["Dashboard", "Generate Keys", "Sign Document", "Verify Document", "Activity History"])

if page == "Dashboard":
    st.subheader("📊 Verification Analytics Dashboard")
    rows = get_activities()
    df = pd.DataFrame(rows)
    if df.empty:
        total = signed = verified = valid = invalid = trusted = 0
    else:
        total = len(df)
        signed = int((df["action"] == "SIGNED").sum())
        verified = int((df["action"] == "VERIFIED").sum())
        valid = int(((df["action"] == "VERIFIED") & (df["signature_status"] == "VALID")).sum())
        invalid = int(((df["action"] == "VERIFIED") & (df["signature_status"] == "INVALID")).sum())
        trusted = int(((df["action"] == "VERIFIED") & (df["trust_status"] == "TRUSTED")).sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total activities", total)
    c2.metric("Documents signed", signed)
    c3.metric("Verification attempts", verified)
    c4.metric("Valid signatures", valid)
    c5, c6 = st.columns(2)
    c5.metric("Invalid signatures", invalid)
    c6.metric("Trusted key matches", trusted)
    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("#### Verification outcomes")
        if verified:
            outcome = pd.DataFrame({"Result": ["Valid", "Invalid"], "Count": [valid, invalid]}).set_index("Result")
            st.bar_chart(outcome)
        else:
            st.info("No verification attempts recorded yet. Verify a document to populate this chart.")
    with right:
        st.markdown("#### Activity types")
        if total:
            activity_counts = df["action"].value_counts().rename_axis("Activity").to_frame("Count")
            st.bar_chart(activity_counts)
        else:
            st.info("No activity recorded yet. Generate keys, sign or verify a document to see analytics.")
    st.markdown("#### Recent activity")
    if rows:
        show = pd.DataFrame(rows).head(8)
        st.dataframe(show[["timestamp", "action", "filename", "signature_status", "trust_status"]],
                     use_container_width=True, hide_index=True)
    else:
        st.info("Your dashboard will automatically update as you use the application.")

elif page == "Generate Keys":
    st.subheader("Generate an RSA key pair")
    owner = st.text_input("Signer / organization label", placeholder="Example: University Examination Office")
    if st.button("Generate RSA-2048 Key Pair", type="primary"):
        try:
            private_pem, public_pem, record_bytes, record = generate_key_pair(owner)
            st.session_state["private_pem"] = private_pem
            st.session_state["public_pem"] = public_pem
            st.session_state["record_bytes"] = record_bytes
            st.success("Key pair and classroom trust record generated.")
            st.write(f"**Owner:** {record['owner']}")
            st.write(f"**Key ID:** `{record['key_id']}`")
            st.write("**SHA-256 fingerprint:**")
            st.code(record["fingerprint_sha256"])
        except Exception as exc:
            st.error(str(exc))
    if "private_pem" in st.session_state:
        st.warning("Keep the private key secret. Do not email it or upload it to a public repository.")
        a, b, c = st.columns(3)
        a.download_button("Download private_key.pem", st.session_state["private_pem"], file_name="private_key.pem", mime="application/x-pem-file")
        b.download_button("Download public_key.pem", st.session_state["public_pem"], file_name="public_key.pem", mime="application/x-pem-file")
        c.download_button("Download trusted_key_record.json", st.session_state["record_bytes"], file_name="trusted_key_record.json", mime="application/json")

elif page == "Sign Document":
    st.subheader("Sign the exact bytes of a document")
    doc = st.file_uploader("Choose document to sign", key="sign_doc")
    private_file = st.file_uploader("Upload signer's private_key.pem", type=["pem"], key="private_key")
    if st.button("Sign Document", type="primary", disabled=(doc is None or private_file is None)):
        try:
            signature = sign_document(doc.getvalue(), private_file.getvalue())
            st.session_state["last_signature"] = signature
            st.session_state["last_signed_name"] = doc.name
            add_activity("SIGNED", doc.name, details="Digital signature generated successfully.")
            st.success("Digital signature created successfully.")
            st.download_button("Download signature file", signature, file_name=doc.name + ".sig", mime="application/octet-stream")
            st.info("Keep the original document, signature file, and matching public key together.")
        except Exception as exc:
            st.error(f"Signing failed: {exc}")

elif page == "Verify Document":
    st.subheader("Verify signature and check the simulated trust record")
    verify_doc = st.file_uploader("Upload original document", key="verify_doc")
    signature_file = st.file_uploader("Upload .sig signature file", key="signature")
    public_file = st.file_uploader("Upload public_key.pem", type=["pem"], key="public_key")
    trust_file = st.file_uploader("Optional: upload trusted_key_record.json", type=["json"], key="trust")
    if st.button("Verify Document", type="primary", disabled=(verify_doc is None or signature_file is None or public_file is None)):
        try:
            signature_ok = verify_signature(verify_doc.getvalue(), signature_file.getvalue(), public_file.getvalue())
            trust = evaluate_trust(public_file.getvalue(), trust_file.getvalue() if trust_file is not None else None)
            signature_status = "VALID" if signature_ok else "INVALID"
            trust_status = "TRUSTED" if trust["trusted"] is True else ("NOT TRUSTED" if trust["trusted"] is False else "NOT CHECKED")
            timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
            interpretation = ("The signature matches the uploaded document and public key." if signature_ok else
                              "Signature verification failed. The document, signature, or public key may be wrong.")
            result = {"filename": verify_doc.name, "timestamp": timestamp,
                      "signature_status": signature_status, "trust_status": trust_status,
                      "owner": trust.get("owner"), "fingerprint": trust["fingerprint"],
                      "interpretation": interpretation}
            st.session_state["last_verification_result"] = result
            add_activity("VERIFIED", verify_doc.name, signature_status, trust_status,
                         trust["fingerprint"], interpretation)
        except Exception as exc:
            st.error(f"Verification could not be completed: {exc}")

    result = st.session_state.get("last_verification_result")
    if result:
        st.divider()
        st.markdown("### Automated verification result")
        lcol, rcol = st.columns(2)
        with lcol:
            st.metric("Digital signature", result["signature_status"])
            if result["signature_status"] == "VALID":
                st.success("Signature matches this exact document and public key.")
            else:
                st.error("Signature verification failed. Possible document tampering or mismatched files.")
        with rcol:
            st.metric("Simulated key trust", result["trust_status"])
            if result["trust_status"] == "TRUSTED":
                st.success("Public key matches an ACTIVE classroom trust record.")
            elif result["trust_status"] == "NOT TRUSTED":
                st.warning("The supplied key did not pass the trust-record check.")
            else:
                st.info("No trust record was supplied; key trust was not checked.")
        st.write("**Public-key SHA-256 fingerprint:**")
        st.code(result["fingerprint"])
        if result.get("owner"):
            st.write(f"**Trust record owner:** {result['owner']}")
        pdf_bytes = create_verification_pdf(result)
        st.download_button("📄 Download Verification Report (PDF)", pdf_bytes,
                           file_name="verification_report.pdf", mime="application/pdf")
        st.caption("A valid signature confirms that the corresponding private key signed these exact bytes. It does not alone prove a person's real-world identity or legal authority.")

elif page == "Activity History":
    st.subheader("🧾 Verification & Signing History")
    rows = get_activities()
    if rows:
        history = pd.DataFrame(rows)
        st.dataframe(history[["timestamp", "action", "filename", "signature_status", "trust_status", "details"]],
                     use_container_width=True, hide_index=True)
        csv_data = history.to_csv(index=False).encode("utf-8")
        st.download_button("Download activity history (CSV)", csv_data,
                           file_name="activity_history.csv", mime="text/csv")
        if st.button("Clear activity history", type="secondary"):
            clear_activities()
            st.success("Activity history cleared. Refresh the page to update the dashboard.")
    else:
        st.info("No activity recorded yet. Sign or verify a document to create history.")

st.divider()
st.caption("For classroom use only. Use synthetic/sample documents. This prototype is not a production document-signing or certificate-authority service. Activity history stores filenames and verification metadata only; it does not store document contents, private keys or signatures.")
