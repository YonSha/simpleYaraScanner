import glob
import os
import yara
from datetime import datetime
from multiprocessing import Value, Process, Manager, cpu_count

# yara rules folder
yara_rules_files = glob.glob("./yara-rules/*.yar", recursive=True)
# files folder to scan
files_to_scan = glob.glob("./yara_test_files/*", recursive=True)

# To prevent ascii files error in win10 files
def is_ascii(s):
    if not s:  # Return True for empty strings
        return True
    return all(ord(c) < 128 for c in s)

def files_scanner(file_chunk,rule_path,result_value,shared_list):
    try:
        rule = yara.compile(rule_path)
    except:
        rule = yara.load(rule_path)

    for file_path in file_chunk:
        if result_value.value > 0:
            break

        is_ascii_path = is_ascii(file_path)

        if not is_ascii_path and os.name == 'nt':
            with open(file_path, 'rb',buffering=1024*1024) as f:
                match = rule.match(data=f.read(),  timeout=30)
        else:
            match = rule.match(file_path, timeout=30)

        if len(match) > 0:
            result_value.value += 1
            shared_list.append(file_path)
            break


# write results to log
def write_to_file(rule_path, file_path,):
    log_message = f"{datetime.now()}: {rule_path} --> "
    log_message += "No malicious found for rule\n" if not file_path else f"{file_path} -> found malicious file!\n"

    # Open the file once and write the message
    with open("./my_matchs.log", 'a+', encoding='utf8') as f:
        f.write(log_message)


def split_into_equal_lists(big_list, num_sublists):
    n = len(big_list)
    size = n // num_sublists
    remainder = n % num_sublists

    sublists = []
    start = 0

    for i in range(num_sublists):
        end = start + size + (1 if i < remainder else 0)
        sublists.append(big_list[start:end])
        start = end

    return sublists

if __name__ == "__main__":

    print("started scan", datetime.now())
    print(f"Found {len(files_to_scan)} Files")
    print(f"Found {len(yara_rules_files)} Yaras")

    with Manager() as manager:
        shared_list = manager.list()
        result_value = Value('i', 0)

        chunks = split_into_equal_lists(files_to_scan,8)

        for rule_path in yara_rules_files:
            processes = []
            result_value.value = 0

            try:
                for chunk in chunks:
                    process = Process(target=files_scanner, args=(chunk, rule_path, result_value, shared_list))
                    processes.append(process)
                    process.start()

                for process in processes:
                    process.join()

                if result_value.value == 0:
                    write_to_file(rule_path, False)
                else:
                    write_to_file(rule_path, shared_list[0])
                    shared_list.pop()
            finally:
                for process in processes:
                    process.terminate()

    print("ended scan", datetime.now())