import glob
import os
import yara
from datetime import datetime

files_to_scan = glob.glob("./yara_test_files/*")
yara_rules_files = glob.glob("./yara-rules/*")


def files_scanner():

    print("started scan", datetime.now())
    print(f"Found {len(files_to_scan)} Files")
    print(f"Found {len(yara_rules_files)} Yaras")
    for rule_path in yara_rules_files:
        if ".yar" not in rule_path:
            continue
        found_malicious = False
        rule = yara.load(rule_path)

        for file_path in files_to_scan:

            if ".yar" not in file_path:
                continue

            is_ascii_path = is_ascii(file_path)

            if not is_ascii_path and os.name == 'nt':
                with open(file_path, 'rb') as f:
                    match = rule.match(data=f.read(),  timeout=30)
            else:
                match = rule.match(file_path, timeout=30)

            if len(match) > 0:
                found_malicious = True
                write_to_file(rule_path, file_path)
                break
        if not found_malicious:
            write_to_file(rule_path, False)

    print("ended scan", datetime.now())


def write_to_file(rule_path, file_path):
    if not file_path:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f" {rule_path} No malicious found for rule")
            f.write("\n")
    else:
        with open("./my_matchs.log", 'a+', encoding='utf8') as f:
            f.write(f" {rule_path} ${file_path} found malicious file!")
            f.write("\n")


def is_ascii(s):
    return all(ord(c) < 128 for c in s)



if __name__ == "__main__":
    files_scanner()
