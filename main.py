import streamlit as st
import requests
import base64, json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

# --- Config ---
BASE_URL = "https://dapacheckerpro.com/wp-content/plugins/dapachecker/"

# --- CryptoJS-like cyphereddata clone ---
def cyphereddata(unix_value: str, r: str = "cryptoJS"):
    unix_value = str(unix_value)
    e = get_random_bytes(256)  # random salt
    a = get_random_bytes(16)   # random IV
    i = PBKDF2(r.encode(), e, dkLen=32, count=999, hmac_hash_module=SHA512)
    cipher = AES.new(i, AES.MODE_CBC, iv=a)
    pad_len = 16 - (len(unix_value.encode()) % 16)
    padded = unix_value.encode() + bytes([pad_len]) * pad_len
    n = cipher.encrypt(padded)

    return {
        "amtext": base64.b64encode(n).decode(),
        "slam_ltol": e.hex(),
        "iavmol": a.hex()
    }

# --- Main function ---
def check_domain(domain: str):
    session = requests.Session()
    # Step 1: get unix.php
    r1 = session.get(BASE_URL + "unix.php")
    if not r1.ok:
        return {"error": "unix.php failed"}
    unix_val = r1.text.strip()

    # Step 2: build payload
    payload = cyphereddata(unix_val)
    payload["domains"] = domain
    headers = {
        "Origin": "https://dapacheckerpro.com",
        "Referer": "https://dapacheckerpro.com/",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }

    # Step 3: POST
    r2 = session.post(BASE_URL + "requests/checkdapa.php",
                      data=json.dumps(payload),
                      headers=headers)
    if not r2.ok:
        return {"error": "checkdapa.php failed"}

    try:
        data = r2.json()
    except:
        return {"error": "Invalid JSON"}

    if not data.get("success"):
        return {"error": data.get("message", "API error")}

    info = list(data["data"].values())[0]
    return {
        "Domain": info.get("fqdn", domain),
        "DA": info.get("domain_authority"),
        "PA": info.get("page_authority"),
        "SS": info.get("spam_score"),

        # "Title": info.get("title")
    }

# --- Streamlit UI ---
st.set_page_config(page_title="Domain Authority Checker", page_icon="🌐")

st.title("🌐 Domain Authority / Page Authority Checker")
st.markdown("Enter domains (one per line) to check DA / PA / Spam Score")

user_input = st.text_area("Type Domain ")

if st.button("Check Authority"):
    domains = [d.strip() for d in user_input.splitlines() if d.strip()]
    results = []
    with st.spinner("Checking domains..."):
        for d in domains:
            res = check_domain(d)
            if "error" in res:
                results.append({"Domain": d, "DA": "-", "PA": "-", "SS": "-", "Title": res["error"]})
            else:
                results.append(res)
    if results:
        st.success("Done ✅")
        st.dataframe(results, use_container_width=True)


