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
from pathlib import Path
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from asn1crypto import cms

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
st.sidebar.title("Uploaded Files")
uploaded_files = st.file_uploader("Upload files", accept_multiple_files=True, type=['exe', 'dll', 'sys', 'bin', 'ps1', 'js', 'hta', 'cmd', 'bat'])
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
        pe = lief.parse(io.BytesIO(binary_data))

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
        
        # Initialize signature details
        metadata['Signatures'] = []

        if pe.has_signatures:
            for sig in pe.signatures:
                sig_info = {'Certificates': [], 'Signer': []}
                
                for cert in sig.certificates:
                    tmp_cert_dict = {}
                    tmp_cert_dict['Subject'] = cert.subject.replace('\\', '').replace('-', ',')
                    tmp_cert_dict['ValidFrom'] = str(datetime(*cert.valid_from))
                    tmp_cert_dict['ValidTo'] = str(datetime(*cert.valid_to))
                    tmp_cert_dict['Signature'] = cert.signature.hex()
                    tmp_cert_dict['SignatureAlgorithmOID'] = cert.signature_algorithm
                    tmp_cert_dict['IsCertificateAuthority'] = cert.is_ca
                    tmp_cert_dict['SerialNumber'] = cert.serial_number.hex()
                    tmp_cert_dict['Version'] = cert.version

                    # Calculate TBS Hashes
                    raw_cert = x509.load_der_x509_certificate(cert.raw, default_backend())
                    tmp_cert_dict['TBS'] = {
                        "MD5": hashlib.md5(raw_cert.tbs_certificate_bytes).hexdigest(),
                        "SHA1": hashlib.sha1(raw_cert.tbs_certificate_bytes).hexdigest(),
                        "SHA256": hashlib.sha256(raw_cert.tbs_certificate_bytes).hexdigest(),
                        "SHA384": hashlib.sha384(raw_cert.tbs_certificate_bytes).hexdigest()
                    }

                    sig_info['Certificates'].append(tmp_cert_dict)

                for signer in sig.signers:
                    tmp_signer_dict = {}
                    tmp_signer_dict['SerialNumber'] = signer.serial_number.hex()
                    tmp_signer_dict['Issuer'] = signer.issuer.replace('\\', '').replace('-', ',')
                    tmp_signer_dict['Version'] = signer.version

                    sig_info['Signer'].append(tmp_signer_dict)

                metadata['Signatures'].append(sig_info)

        return metadata
    except Exception as e:
        st.error(f"Failed to extract metadata: {str(e)}")
        return {}

def extract_script_metadata(file_data, filename):
    metadata = {}
    metadata['filename'] = filename
    metadata['sha1'] = hashlib.sha1(file_data).hexdigest().upper()
    metadata['sha256'] = hashlib.sha256(file_data).hexdigest().upper()

    try:
        script_content = file_data.decode('utf-8')
    except UnicodeDecodeError:
        try:
            script_content = file_data.decode('utf-16-le')
        except UnicodeDecodeError:
            st.error(f"Unable to decode script content for {filename}")
            return metadata

    sig_match = re.search(r"# SIG # Begin signature block(.+?)# SIG # End signature block", script_content, re.DOTALL)
    if sig_match:
        sig_block = sig_match.group(1)
        sig_data = ''.join(re.findall(r"([A-Za-z0-9+/=\r\n]+)", sig_block)).replace("\r", "").replace("\n", "")
        
        try:
            der_data = base64.b64decode(sig_data)
            content_info = cms.ContentInfo.load(der_data)
            signed_data = content_info['content']
            certs = signed_data['certificates']
            
            if certs:
                metadata['certificates'] = []
                for cert_choice in certs:
                    cert = cert_choice.chosen
                    cert_der = cert.dump()
                    crypto_cert = x509.load_der_x509_certificate(cert_der)
                    
                    cert_info = {}
                    cert_info['subject'] = crypto_cert.subject.rfc4514_string()
                    cert_info['issuer'] = crypto_cert.issuer.rfc4514_string()
                    cert_info['subject_cn'] = extract_cn(crypto_cert.subject)
                    cert_info['issuer_cn'] = extract_cn(crypto_cert.issuer)
                    cert_info['serial_number'] = crypto_cert.serial_number
                    cert_info['not_valid_before'] = crypto_cert.not_valid_before
                    cert_info['not_valid_after'] = crypto_cert.not_valid_after
                    
                    tbs_hash = hashes.Hash(hashes.SHA1())
                    tbs_hash.update(crypto_cert.tbs_certificate_bytes)
                    cert_info['tbs_sha1'] = tbs_hash.finalize().hex().upper()
                    
                    try:
                        cert_info['is_ca'] = crypto_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value.ca
                    except x509.ExtensionNotFound:
                        cert_info['is_ca'] = False
                    
                    cert_info['cert_publisher'] = cert_info['subject_cn']
                    
                    metadata['certificates'].append(cert_info)
            else:
                st.warning("No certificates found in the signature.")
        except Exception as e:
            st.error(f"Error processing certificate for {filename}: {str(e)}")
    else:
        st.info(f"No signature block found in {filename}")

    return metadata

def extract_cn(name):
    for attr in name:
        if attr.oid == x509.NameOID.COMMON_NAME:
            return attr.value
    return "Unknown"

def generate_signer_rule(metadata, action="Allow"):
    if 'signer' in metadata and 'certificates' in metadata:
        leaf_cert = metadata['certificates'][0]  # Assuming the first cert is the leaf
        issuer_cert = metadata['certificates'][1] if len(metadata['certificates']) > 1 else None

        if issuer_cert:
            signer_id = sanitize_id(f"SIGNER_{issuer_cert['cert_publisher']}")
            signer_rule = f'<Signer Name="{issuer_cert["cert_publisher"]}" ID="{signer_id}">\n'
            signer_rule += f'  <CertRoot Type="TBS" Value="{issuer_cert["tbs_sha1"]}" />\n'
            signer_rule += f'  <CertPublisher Value="{leaf_cert["cert_publisher"]}" />\n'
            signer_rule += '</Signer>'
            signer_rule_ref = f'<{"Denied" if action == "Deny" else "Allowed"}Signer SignerId="{signer_id}" />'
            
            return signer_rule, signer_rule_ref
    
    return None, None

if selected_file:
    file_data = selected_file.read()
    filename = selected_file.name

    if filename.lower().endswith(('.exe', '.dll', '.sys', '.bin')):
        metadata = extract_metadata(file_data, filename)

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
                for cert_chain in metadata.get('Certificates', []):
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
                    st.text_area(f"{rule['type']} Rule Reference", value=rule['ref'], height=70)

            # Update rule generation
            st.subheader("Generated Rules")
            
            if metadata.get('Signatures'):
                for sig_info in metadata['Signatures']:
                    for cert in sig_info['Certificates']:
                        if not cert['IsCertificateAuthority']:
                            signer_id = sanitize_id(f"SIGNER_{cert['Subject']}")
                            signer_rule = f'<Signer Name="{cert["Subject"]}" ID="{signer_id}">\n  <CertRoot Type="TBS" Value="{cert["TBS"]["SHA1"]}" />\n  <CertPublisher Value="{cert["Subject"]}" />\n</Signer>'
                            signer_rule_ref = f'<{"Denied" if action == "Deny" else "Allowed"}Signer SignerId="{signer_id}" />'
                            
                            with st.expander("Signer Rule"):
                                st.code(f"{signer_rule}\n\n{signer_rule_ref}")

    else:  # Script file
        metadata = extract_script_metadata(file_data, filename)

        if metadata:
            st.subheader("Script Details")
            details = ""
            for key, value in metadata.items():
                if key != 'certificates':
                    details += f"{key}: {value}\n"
            st.text_area("Basic Details", value=details, height=200, max_chars=None)

            if 'certificates' in metadata:
                st.subheader("Certificate Chain")
                for i, cert in enumerate(metadata['certificates']):
                    with st.expander(f"Certificate {i+1}: {cert['subject_cn']}"):
                        for key, value in cert.items():
                            st.write(f"{key}: {value}")

            st.subheader("Action")
            action = st.radio("Action", ["Allow", "Deny"], index=0, format_func=lambda x: "Allow" if x == "Allow" else "Deny", key="action")

            st.subheader("Generated Rules")
            
            sha1_value = metadata["sha1"]
            sha256_value = metadata["sha256"]
            
            sha1_rule_id = sanitize_id(f"{action}_{filename}_SHA1")
            sha256_rule_id = sanitize_id(f"{action}_{filename}_SHA256")
            
            sha1_xml_rule = f'<{action} ID="{sha1_rule_id}" FriendlyName="{filename} Hash Sha1" Hash="{sha1_value}" />'
            sha256_xml_rule = f'<{action} ID="{sha256_rule_id}" FriendlyName="{filename} Hash Sha256" Hash="{sha256_value}" />'
            
            sha1_rule_ref = f'<FileRuleRef RuleID="{sha1_rule_id}" />'
            sha256_rule_ref = f'<FileRuleRef RuleID="{sha256_rule_id}" />'
            
            with st.expander("Hash Rules"):
                st.code(f"{sha1_xml_rule}\n{sha256_xml_rule}\n\n{sha1_rule_ref}\n{sha256_rule_ref}")
            
            if 'certificates' in metadata and metadata['certificates']:
                leaf_cert = metadata['certificates'][0]  # Assuming the first cert is the leaf
                issuer_cert = metadata['certificates'][1] if len(metadata['certificates']) > 1 else leaf_cert

                signer_id = sanitize_id(f"SIGNER_{leaf_cert['subject_cn']}")
                signer_rule = f'<Signer Name="{leaf_cert["subject_cn"]}" ID="{signer_id}">\n'
                signer_rule += f'  <CertRoot Type="TBS" Value="{issuer_cert["tbs_sha1"]}" />\n'
                signer_rule += f'  <CertPublisher Value="{leaf_cert["subject_cn"]}" />\n'
                signer_rule += '</Signer>'
                signer_rule_ref = f'<{"Denied" if action == "Deny" else "Allowed"}Signer SignerId="{signer_id}" />'
                
                with st.expander("Signer Rule"):
                    st.code(f"{signer_rule}\n\n{signer_rule_ref}")
            else:
                st.warning("No valid certificate chain found in the script. Unable to generate Signer Rule.")

    if st.button("Save Rule"):
        st.sidebar.success(f"Rule saved for {selected_file.name}")

if st.sidebar.button("Export Policy"):
    st.sidebar.success("Policy exported successfully.")

