#!/usr/bin/python3
import string
import secrets
import math
import argparse
import logging
import collections
import subprocess
import asyncio

# Constants
CHARSET = string.ascii_letters + string.digits + string.punctuation

async def calculate_entropy_shannon(password):
    char_count = collections.Counter(password)
    charset_length = len(CHARSET)
    entropy = 0

    for char in char_count:
        char_probability = char_count[char] / len(password)
        entropy -= char_probability * math.log2(char_probability)

    return entropy

async def calculate_entropy_nist(password):
    charset_size = len(CHARSET)
    password_length = len(password)
    possible_combinations = charset_size ** password_length
    entropy_bits = math.log2(possible_combinations)
    return entropy_bits

async def generate_password(length):
    return ''.join(secrets.choice(CHARSET) for _ in range(length))

async def generate_sample_passwords_async(password_length, num_samples):
    password_list = []

    for _ in range(num_samples):
        password = await generate_password(password_length)
        password_list.append(password)

    return password_list

async def calculate_and_display_entropy_async(passwords):
    min_entropy = float('inf')
    max_entropy = 0
    entropy_sum = 0

    for password in passwords:
        entropy_bits = await calculate_entropy_shannon(password)
        entropy_sum += entropy_bits

        min_entropy = min(min_entropy, entropy_bits)
        max_entropy = max(max_entropy, entropy_bits)

    average_entropy = entropy_sum / len(passwords)

    logging.info(f"Entropy Range: {min_entropy:.2f} - {max_entropy:.2f} bits")
    logging.info(f"Average Entropy: {average_entropy:.2f} bits")

    return max_entropy

async def calculate_entropy_keepassxc_async(password):
    try:
        cmd = ["keepassxc-cli", "estimate", "-a", f'"{password}"']
        entropy_result = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = await entropy_result.communicate()

        entropy_lines = stdout.decode().strip().split('\n')

        for line in entropy_lines:
            if "Entropy" in line:
                parts = line.split()
                if len(parts) >= 4:
                    entropy_bits = float(parts[3])
                    return entropy_bits

        logging.error("Failed to estimate entropy using Keepassxc.")
        return 0.0
    except subprocess.CalledProcessError as e:
        logging.error("Failed to run keepassxc-cli command.")
        logging.error("Error message: " + e.output.decode())
        return 0.0

async def generate_eligible_passwords(password_list, max_entropy):
    eligible_passwords = []

    for password in password_list:
        entropy = await calculate_entropy_shannon(password)

        if entropy >= max_entropy:
            eligible_passwords.append((password, entropy))

    return eligible_passwords

async def calculate_entropy_keepassxc_async(password):
    try:
        cmd = ["keepassxc-cli", "estimate", "-a", f'"{password}"']
        entropy_result = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = await entropy_result.communicate()

        entropy_lines = stdout.decode().strip().split('\n')

        for line in entropy_lines:
            if "Entropy" in line:
                parts = line.split()
                if len(parts) >= 4:
                    entropy_bits = float(parts[3])
                    return entropy_bits

        logging.error("Failed to estimate entropy using Keepassxc.")
        return 0.0
    except subprocess.CalledProcessError as e:
        logging.error("Failed to run keepassxc-cli command.")
        logging.error("Error message: " + e.output.decode())
        return 0.0

async def calculate_and_display_entropy_keepassxc_async(sample_passwords):
    entropy_values = await asyncio.gather(*[calculate_entropy_keepassxc_async(password) for password in sample_passwords])
    min_entropy = min(entropy_values)
    max_entropy = max(entropy_values)
    average_entropy = sum(entropy_values) / len(entropy_values)

    logging.info(f"Entropy Range: {min_entropy:.2f} - {max_entropy:.2f} bits")
    logging.info(f"Average Entropy: {average_entropy:.2f} bits")

    strongest_password = sample_passwords[entropy_values.index(max_entropy)]
    logging.info(f"Password with Highest Entropy: {strongest_password} (Entropy: {max_entropy:.2f} bits)")

    entropy_requirement = max_entropy
    min_accepted_entropy = max_entropy - args.cushion

    non_duplicated_passwords = []
    while len(non_duplicated_passwords) < args.generate:
        password = await generate_password(password_length)
        entropy = await calculate_entropy_keepassxc_async(password)
        if min_accepted_entropy <= entropy <= entropy_requirement and password not in non_duplicated_passwords:
            non_duplicated_passwords.append(password)

    if non_duplicated_passwords:
        chosen_password = secrets.choice(non_duplicated_passwords)
        logging.info(f"Chosen Password from Non-Duplicated: {chosen_password} (Entropy: {entropy_requirement:.2f} bits)")
    else:
        logging.warning("No non-duplicated passwords meeting the entropy requirement.")

async def main_async():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description="Generate passwords and calculate entropy.")
    parser.add_argument("--length", type=int, help="Password length", required=True)
    parser.add_argument("--samples", type=int, default=1000, help="Number of sample passwords")
    parser.add_argument("--method", choices=["shannon", "nist", "keepassxc"], default="shannon", help="Entropy calculation method")
    parser.add_argument("--cushion", type=float, default=3.0, help="Entropy cushion")
    parser.add_argument("--generate", type=int, default=50, help="Number of passwords to generate")
    args = parser.parse_args()

    password_length = args.length
    entropy_method = args.method
    num_samples = args.samples

    if entropy_method == "shannon":
        logging.info("Generating sample passwords for entropy calculation...")

        password_list = await generate_sample_passwords_async(password_length, num_samples)
        max_entropy = await calculate_and_display_entropy_async(password_list)

        eligible_passwords = await generate_eligible_passwords(password_list, max_entropy)

        if eligible_passwords:
            logging.info(f"Generated {len(eligible_passwords)} passwords meeting the entropy requirement.")

            password_counts = collections.Counter(password_list)

            non_duplicated_passwords = []
            for password, _ in eligible_passwords:
                if password_counts[password] == 1:
                    non_duplicated_passwords.append(password)

            total_duplicates = len(eligible_passwords) - len(non_duplicated_passwords)
            logging.info(f"Total Duplicates: {total_duplicates}")

            sorted_passwords_by_count = sorted(password_counts, key=lambda x: password_counts[x], reverse=True)
            most_common_password = sorted_passwords_by_count[0]
            duplicates_of_most_common = password_counts[most_common_password]
            logging.info(f"Password with Most Duplicates: {most_common_password} (Generated {duplicates_of_most_common} times)")

            if non_duplicated_passwords:
                selected_password = secrets.choice(non_duplicated_passwords)
                selected_password_entropy = await calculate_entropy_shannon(selected_password)
                logging.info(f"Chosen Password from Non-Duplicated: {selected_password} (Entropy: {selected_password_entropy:.2f} bits)")
            else:
                logging.warning("No non-duplicated passwords meeting the entropy requirement.")
        else:
            logging.warning("No passwords meeting the entropy requirement.")

    elif entropy_method == "nist":
        password_list = await generate_sample_passwords_async(password_length, args.samples)
        chosen_password = secrets.choice(password_list)
        logging.info(f"Chosen Password from NIST: {chosen_password}")

    elif entropy_method == "keepassxc":
        logging.info("Generating sample passwords for entropy calculation...")

        sample_passwords = await generate_sample_passwords_async(password_length, num_samples)
        await calculate_and_display_entropy_keepassxc_async(sample_passwords)

asyncio.run(main_async())

