import streamlit as st
import os
import hashlib
import lief
import io
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime
import re

def sanitize_id(id_string, prefix='ID'):
    # Remove all non-alphanumeric characters except underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', id_string.replace('-', '_').replace(' ', '_'))
    # Ensure the ID starts with a letter
    if not sanitized[0].isalpha():
        sanitized = f"{prefix}_{sanitized}"
    return sanitized.upper()

st.set_page_config(page_title="WDAC Meta Extraction", page_icon="🛡️", layout="wide")

# logo_path = "assets/logo.png"
# st.image(logo_path, width=150)

st.markdown(
    """
    <style>
    .logo-links {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 20px;
    }
    .logo-links a {
        text-decoration: none;
        color: inherit;
    }
    .logo-links img {
        width: 24px;
        height: 24px;
    }
    </style>
    <div class="logo-links">
        <a href="https://magicsword.io" target="_blank">
            <img src="https://magicsword.io/favicon.ico" alt="Magic Sword"/> magicsword.io
        </a>
        <a href="https://x.com/magicswordio" target="_blank">
            <img src="https://abs.twimg.com/favicons/twitter.ico" alt="Twitter"/> Twitter
        </a>
        <a href="https://github.com/magicsword-io/" target="_blank">
            <img src="https://github.com/favicon.ico" alt="GitHub"/> GitHub
        </a>
        <a href="https://medium.com/magicswordio" target="_blank">
            <img src="https://medium.com/favicon.ico" alt="Medium"/> Medium
        </a>
    </div>
    """,
    unsafe_allow_html=True
)

# Title
st.title('🛡️ WDAC Meta Extraction')

# Sidebar for file selection
st.sidebar.title("Uploaded Binaries")
uploaded_files = st.file_uploader("Upload binaries", accept_multiple_files=True, type=['exe', 'dll', 'sys', 'bin'])
selected_file = st.sidebar.radio("Select a file to inspect:", uploaded_files, format_func=lambda x: x.name if x else "No files uploaded")

def get_hashes(binary_data):
    md5 = hashlib.md5(binary_data).hexdigest()
    sha1 = hashlib.sha1(binary_data).hexdigest()
    sha256 = hashlib.sha256(binary_data).hexdigest()
    pe = lief.PE.parse(io.BytesIO(binary_data))
    authenticode_hash = pe.authentihash(lief.PE.ALGORITHMS.SHA_256).hex() if pe else None
    return md5, sha1, sha256, authenticode_hash

def extract_cn(subject):
    # Parse the subject to extract the Common Name (CN)
    for attribute in subject:
        if attribute.oid == NameOID.COMMON_NAME:
            return attribute.value
    return "Unknown"

def extract_metadata(binary_data, filename):
    try:
        pe = lief.PE.parse(io.BytesIO(binary_data))

        if pe is None:
            return {}
        
        metadata = {}
        # Extract hashes
        md5, sha1, sha256, authenticode_hash = get_hashes(binary_data)
        
        # Basic binary details
        metadata["Filename"] = filename
        metadata["MD5"] = md5
        metadata["SHA1"] = sha1
        metadata["SHA256"] = sha256
        metadata["Authenticode Hash"] = authenticode_hash
        metadata["Creation Time"] = datetime.fromtimestamp(pe.header.time_date_stamps).strftime('%Y-%m-%d %H:%M:%S')

        # Version info and other details
        try:
            version_info = pe.resources_manager.version.string_file_info.langcode_items[0].items
            metadata['Company Name'] = version_info.get('CompanyName', b'').decode("utf-8")
            metadata['File Description'] = version_info.get('FileDescription', b'').decode("utf-8")
            metadata['Internal Name'] = version_info.get('InternalName', b'').decode("utf-8")
            metadata['Original Filename'] = version_info.get('OriginalFilename', b'').decode("utf-8")
            metadata['Product Name'] = version_info.get('ProductName', b'').decode("utf-8")
        except Exception as e:
            metadata.update({
                'Company Name': "",
                'File Description': "",
                'Internal Name': "",
                'Original Filename': "",
                'Product Name': "",
            })
        
        # Initialize certificate details list
        metadata['Certificates'] = []
        
        if pe.has_signatures:
            for signature in pe.signatures:
                cert_chain = []
                issuer_tbs_sha1 = None
                for lief_cert in signature.certificates:
                    # Convert LIEF certificate to cryptography certificate
                    cert = x509.load_der_x509_certificate(lief_cert.raw, default_backend())
                    
                    # Classify the certificate
                    is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    try:
                        ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
                        is_code_signing = any(usage.dotted_string == "1.3.6.1.5.5.7.3.3" for usage in ext_key_usage.value)
                    except x509.ExtensionNotFound:
                        is_code_signing = False

                    cert_type = "CA" if is_ca else "Leaf (Code Signing)" if is_code_signing else "Intermediate"
                    
                    # Calculate TBS Hashes
                    tbs_hashes = {
                        "MD5": hashlib.md5(cert.tbs_certificate_bytes).hexdigest(),
                        "SHA1": hashlib.sha1(cert.tbs_certificate_bytes).hexdigest(),
                        "SHA256": hashlib.sha256(cert.tbs_certificate_bytes).hexdigest(),
                        "SHA384": hashlib.sha384(cert.tbs_certificate_bytes).hexdigest()
                    }

                    if cert_type == "CA" or cert_type == "Intermediate":
                        issuer_tbs_sha1 = tbs_hashes["SHA1"]

                    cert_details = {
                        "Type": cert_type,
                        "Issuer CN": extract_cn(cert.issuer),
                        "Subject CN": extract_cn(cert.subject),
                        "Serial Number": str(cert.serial_number),
                        "Validity Start": cert.not_valid_before_utc,
                        "Validity End": cert.not_valid_after_utc,
                        "Is CA": is_ca,
                        "Is Code Signing": is_code_signing,
                        "TBS Hashes": tbs_hashes,
                        "Issuer TBS SHA1": issuer_tbs_sha1
                    }
                    cert_chain.append(cert_details)
                metadata['Certificates'].append(cert_chain)
        
        return metadata
    except Exception as e:
        st.error(f"Failed to extract metadata: {str(e)}")
        return {}
    
if selected_file:
    binary_data = selected_file.read()

    filename = selected_file.name

    metadata = extract_metadata(binary_data, filename)

    if metadata:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Binary Details")
            details = ""
            for key, value in metadata.items():
                if key != 'Certificates':
                    details += f"{key.replace('_', ' ')}: {value}\n"
            st.text_area("Extracted", value=details, height=200, max_chars=None)

        with col2:
            st.subheader("Certificate Details")
            sorted_cert_chains = []
            for cert_chain in metadata['Certificates']:
                sorted_chain = sorted(cert_chain, key=lambda x: {"CA": 0, "Intermediate": 1, "Leaf (Code Signing)": 2}.get(x['Type'], 3))
                sorted_cert_chains.append(sorted_chain)

            for cert_chain in sorted_cert_chains:
                for cert in cert_chain:
                    if cert['Type'] == "Leaf (Code Signing)":
                        cert_title = f"🍂 {cert['Type']} > {cert['Subject CN']}"
                    else:
                        cert_title = f"{cert['Type']} > {cert['Subject CN']}"
                    with st.expander(f"{cert_title} Details"):
                        for cert_key, cert_value in cert.items():
                            if cert_key == "TBS Hashes":
                                st.write("TBS Hashes:")
                                for hash_type, hash_value in cert_value.items():
                                    st.write(f"  {hash_type}: {hash_value}")
                            else:
                                st.write(f"{cert_key}: {cert_value}")

        # Action
        st.subheader("Detection")
        col1, col2, col3 = st.columns(3)
        with col1:
            publisher = st.checkbox("Publisher", value=False)
            leaf_certificate = st.checkbox("Leaf Certificate", value=True)
            hash_rule = st.checkbox("Hash", value=True)
            file_name_rule = st.checkbox("File Name", value=True)
        with col2:
            action = st.radio("Action", ["Allow", "Deny"], index=1, format_func=lambda x: "Allow" if x == "Allow" else "Deny", key="action")

        # Rule output
        st.subheader("Generated Rules")
        rules = []

        if leaf_certificate:
            leaf_certs = [cert for cert_chain in metadata.get('Certificates', []) for cert in cert_chain if cert['Is Code Signing'] and not cert['Is CA']]
            for cert in leaf_certs:
                issuer_cert = next((c for c in cert_chain if c['Subject CN'] == cert['Issuer CN']), None)
                if issuer_cert:
                    issuer_tbs_sha1 = issuer_cert['TBS Hashes']['SHA1']
                    signer_id = sanitize_id(f"SIGNER_{cert['Issuer CN']}")
                    rule_content = f'<Signer ID="{signer_id}" Name="{cert["Issuer CN"]}">\n  <CertRoot Type="TBS" Value="{issuer_tbs_sha1}" />\n  <CertPublisher Value="{cert["Subject CN"]}" />\n</Signer>'
                    rule_ref = f'<DeniedSigner SignerId="{signer_id}" />' if action == "Deny" else f'<AllowedSigner SignerId="{signer_id}" />'
                    rules.append({"type": "Leaf Certificate", "content": rule_content, "ref": rule_ref})

        if publisher:
            for cert_chain in metadata.get('Certificates', []):
                ca_cert = next((cert for cert in cert_chain if cert['Type'] == "CA"), None)
                if ca_cert:
                    signer_id = sanitize_id(f"SIGNER_{ca_cert['Issuer CN']}")
                    rule_content = f'<Signer Name="{ca_cert["Issuer CN"]}" ID="{signer_id}">\n  <CertRoot Type="TBS" Value="{ca_cert["TBS Hashes"]["SHA1"]}" />\n  <CertPublisher Value="{ca_cert["Subject CN"]}" />\n</Signer>'
                    rule_ref = f'<DeniedSigner SignerId="{signer_id}" />' if action == "Deny" else f'<AllowedSigner SignerId="{signer_id}" />'
                    rules.append({"type": "Publisher", "content": rule_content, "ref": rule_ref})

        if hash_rule:
            authentihash_value = metadata["Authenticode Hash"]
            rule_id = sanitize_id(f"{action}_{filename}_AUTHENTIHASH")
            xml_rule = f'<{action} ID="{rule_id}" FriendlyName="{filename} Authenticode Hash" Hash="{authentihash_value}" />'
            rule_ref = f'<FileRuleRef RuleID="{rule_id}" />'
            rules.append({"type": "Authenticode Hash", "content": xml_rule, "ref": rule_ref})

        if file_name_rule:
            original_filename = metadata.get('Original Filename', '')
            if original_filename:
                filename_id = sanitize_id(f"{action}_{original_filename}")
                if action == "Allow":
                    file_name_rule_content = f'<Allow ID="{filename_id}" FriendlyName="{original_filename} FileRule" FileName="{original_filename}" MinimumFileVersion="0.0.0.0" MaximumFileVersion="65355.65355.65355.65355" />'
                else:
                    file_name_rule_content = f'<Deny ID="{filename_id}" FriendlyName="{original_filename}" FileName="{original_filename}" MinimumFileVersion="0.0.0.0" MaximumFileVersion="65355.65355.65355.65355" />'
                rule_ref = f'<FileRuleRef RuleID="{filename_id}" />'
                rules.append({"type": f"{action} File Name", "content": file_name_rule_content, "ref": rule_ref})
            else:
                st.error("Original Filename not found. Unable to generate 'File Name' rule.")

        for rule in rules:
            with st.expander(f"{rule['type']} Rule"):
                st.text_area(f"{rule['type']} Rule", value=rule['content'], height=100)
                st.text_area(f"{rule['type']} Rule Reference", value=rule['ref'], height=50)


        if st.button("Save Rule"):
            st.sidebar.success(f"Rule saved for {selected_file.name}")

if st.sidebar.button("Export Policy"):
    st.sidebar.success("Policy exported successfully.")