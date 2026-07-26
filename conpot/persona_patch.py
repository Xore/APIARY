#!/usr/bin/env python3
"""Create explicit, validated Siemens identities from Conpot's protocol files."""
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

ROOT = Path("/usr/lib/python3.11/site-packages/conpot/templates")
BASE = ROOT / "default"
PERSONAS = {
    "s7_200": {
        "unit": "S7-200", "description": "Siemens S7-226 compact controller",
        "FacilityName": "Rheinwerk Municipal Water", "SystemName": "Raw Water Intake",
        "SystemDescription": "PLC-INTAKE-01", "sysContact": "OT Operations",
        "sysLocation": "Intake Station / Cabinet A", "sysObjectID": "1.3.6.1.4.1.4196.1.1",
        "s7_id": "S C-RW2A22602019", "s7_module_type": "CPU 226 CN REL 02.01",
        "firmware": "V02.01", "hardware": "6ES7 216-2BD23-0XB8",
    },
    "s7_1200": {
        "unit": "S7-1200", "description": "Siemens SIMATIC S7-1215C compact controller",
        "FacilityName": "Rheinwerk Municipal Water", "SystemName": "Filter Hall 2",
        "SystemDescription": "PLC-FILTER-02", "sysContact": "Water Treatment OT",
        "sysLocation": "Treatment Plant / Filter Hall 2", "sysObjectID": "1.3.6.1.4.1.4196.1.2",
        "s7_id": "S C-RW4B12152024", "s7_module_type": "CPU 1215C DC/DC/DC",
        "firmware": "V04.05.01", "hardware": "6ES7 215-1AG40-0XB0",
    },
    "s7_1500": {
        "unit": "S7-1500", "description": "Siemens SIMATIC S7-1516 process controller",
        "FacilityName": "NordChem Process Industries", "SystemName": "Reactor Line 4",
        "SystemDescription": "PLC-REACTOR-04", "sysContact": "Process Control Engineering",
        "sysLocation": "Building P4 / Control Cabinet 4A", "sysObjectID": "1.3.6.1.4.1.4196.1.3",
        "s7_id": "S C-NC7F15162025", "s7_module_type": "CPU 1516-3 PN/DP",
        "firmware": "V02.09.04", "hardware": "6ES7 516-3AN02-0AB0",
    },
}

def quoted(value: str) -> str:
    return f'"{value}"'

for name, values in PERSONAS.items():
    target = ROOT / name
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(BASE, target)
    tree = ET.parse(target / "template.xml")
    root = tree.getroot()
    for entity in root.findall("./template/entity"):
        if entity.get("name") in ("unit", "description"):
            entity.text = values[entity.get("name")]
    mappings = root.find("./databus/key_value_mappings")
    existing = {node.get("name"): node for node in mappings.findall("key")}
    for key, value in values.items():
        if key in ("unit", "description", "firmware", "hardware"):
            continue
        node = existing.get(key)
        if node is None:
            node = ET.SubElement(mappings, "key", {"name": key})
            ET.SubElement(node, "value", {"type": "value"})
        node.find("value").text = quoted(value)
    for key, value in {"s7_firmware": values["firmware"], "s7_hardware": values["hardware"],
                       "s7_location": values["sysLocation"]}.items():
        node = ET.SubElement(mappings, "key", {"name": key})
        ET.SubElement(node, "value", {"type": "value"}).text = quoted(value)
    ET.indent(tree, space="    ")
    tree.write(target / "template.xml", encoding="unicode")

    s7_path = target / "s7comm/s7comm.xml"
    s7 = ET.parse(s7_path)
    s7root = s7.getroot()
    s7root.find(".//hardware_identification").text = "s7_hardware"
    s7root.find(".//firmware_identification").text = "s7_firmware"
    s7root.find(".//location").text = "s7_location"
    ET.indent(s7, space="    ")
    s7.write(s7_path, encoding="unicode")

    check = ET.parse(target / "template.xml")
    rendered = " ".join((node.text or "") for node in check.findall(".//value"))
    for required in (values["FacilityName"], values["SystemName"], values["s7_id"], values["firmware"]):
        if required not in rendered:
            raise SystemExit(f"persona {name} failed validation: missing {required}")

def patch_existing(name, entities, values):
    """Patch a shipped non-S7 template while preserving its protocol layout."""
    path = ROOT / name / "template.xml"
    tree = ET.parse(path)
    root = tree.getroot()
    for entity in root.findall("./template/entity"):
        if entity.get("name") in entities:
            entity.text = entities[entity.get("name")]
    nodes = {node.get("name"): node.find("value") for node in root.findall("./databus/key_value_mappings/key")}
    for key, value in values.items():
        if key not in nodes:
            raise SystemExit(f"{name}: missing expected key {key}")
        nodes[key].text = repr(value) if isinstance(value, str) else str(value)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="unicode")

patch_existing("IEC104",
    {"unit": "Substation RTU", "vendor": "Siemens", "description": "ElbeGrid 110/20 kV substation IEC 60870-5-104 RTU"},
    {"FacilityName": "ElbeGrid Distribution", "SystemName": "RTU-SUB17-A",
     "SystemDescription": "SICAM A8000 / CP-8050", "sysContact": "Grid Control Centre",
     "sysName": "rtu-sub17-a", "sysLocation": "Substation 17 / Relay Room",
     "CommonAddress": "0x0117"})

patch_existing("guardian_ast",
    {"unit": "Guardian AST tank monitor", "vendor": "Veeder-Root", "description": "NorthFuel station 042 automatic tank gauge"},
    {"station_name": "NORTHFUEL STATION 042", "product1": "DIESEL", "product2": "E10",
     "product3": "SUPER PLUS", "product4": "ADBLUE", "vol1": 18472.6, "vol2": 12631.4,
     "vol3": 8842.1, "vol4": 3270.8, "temp1": 13.8, "temp2": 14.1,
     "temp3": 13.6, "temp4": 14.0})

patch_existing("kamstrup_382",
    {"unit": "MULTICAL 382", "vendor": "Kamstrup", "description": "Stadtwaerme West loop billing heat meter"},
    {"register_13": 38204217, "register_51": 1874263, "register_54": 24072100,
     "register_55": 24062100, "software_version": "6.2 (E7)",
     "device_name": "HEATMETER-WEST-0382", "mac_address": "00:13:EA:42:03:82",
     "use_dhcp": "NO", "ip_addr": "10.42.38.82", "ip_gateway": "10.42.38.1",
     "ip_subnet": "255.255.255.0", "kap_a_server_hostname": "meter-gw-01.stadtwaerme.local",
     "kap_a_server_ip": "10.42.38.10"})
