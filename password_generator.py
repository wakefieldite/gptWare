#!/usr/bin/python3
import string
import secrets
import math
import argparse
import logging
import collections
import os
import subprocess

# Constants
CHARSET = string.ascii_letters + string.digits + string.punctuation

def calculate_entropy_shannon(password):
    """
    Calculate Shannon entropy for a given password.
    """
    char_count = collections.Counter(password)
    charset_length = len(CHARSET)
    entropy = 0

    for char in char_count:
        char_probability = char_count[char] / len(password)
        entropy -= char_probability * math.log2(char_probability)

    return entropy

def calculate_entropy_nist(password):
    """
    Calculate NIST entropy for a given password.
    """
    charset_size = len(CHARSET)
    password_length = len(password)
    possible_combinations = charset_size ** password_length
    entropy_bits = math.log2(possible_combinations)
    return entropy_bits

def generate_password(length):
    """
    Generate a random password of the given length.
    """
    return ''.join(secrets.choice(CHARSET) for _ in range(length))

def generate_sample_passwords(password_length, num_samples):
    """
    Generate a list of sample passwords for entropy calculation.
    """
    logging.info("Generating sample passwords for entropy calculation...")
    password_list = [generate_password(password_length) for _ in range(num_samples)]
    return password_list

def calculate_and_display_entropy(passwords):
    """
    Calculate and display entropy statistics for a list of passwords.
    """
    min_entropy = float('inf')
    max_entropy = 0
    entropy_sum = 0

    for password in passwords:
        entropy_bits = calculate_entropy_shannon(password)
        entropy_sum += entropy_bits

        min_entropy = min(min_entropy, entropy_bits)
        max_entropy = max(max_entropy, entropy_bits)

    average_entropy = entropy_sum / len(passwords)

    logging.info(f"Entropy Range: {min_entropy:.2f} - {max_entropy:.2f} bits")
    logging.info(f"Average Entropy: {average_entropy:.2f} bits")

    return max_entropy

def calculate_entropy_keepassxc(password):
    """
    Calculate entropy using the Keepassxc method for a given password.
    """
    try:
        cmd = ["keepassxc-cli", "estimate", "-a", f'"{password}"']
        entropy_result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        entropy_lines = entropy_result.strip().split('\n')

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
        logging.error("Error message: " + e.output)
        return 0.0

def main():
    """
    Main function to generate passwords and calculate entropy.
    """
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
        password_list = generate_sample_passwords(password_length, args.samples)
        max_entropy = calculate_and_display_entropy(password_list)
        entropy_requirement = max_entropy

        logging.info("Generating passwords meeting the entropy requirement...")

        non_duplicated_passwords = []
        password_counts = []

        for password in password_list:
            entropy = calculate_entropy_shannon(password)

            if entropy >= entropy_requirement:
                if password not in password_counts:
                    password_counts.append(password)
                    non_duplicated_passwords.append(password)

        total_duplicates = args.samples - len(non_duplicated_passwords)
        logging.info(f"Total Duplicates: {total_duplicates}")

        sorted_passwords_by_count = sorted(password_counts, key=lambda x: password_counts.count(x), reverse=True)
        most_common_password = sorted_passwords_by_count[0]
        logging.info(f"Password with Most Duplicates: {most_common_password} (Generated {password_counts.count(most_common_password)} times)")

        if non_duplicated_passwords:
            selected_password = secrets.choice(non_duplicated_passwords)
            logging.info(f"Chosen Password from Non-Duplicated: {selected_password}")
        else:
            logging.warning("No non-duplicated passwords meeting the entropy requirement.")

    elif entropy_method == "nist":
        password_list = generate_sample_passwords(password_length, args.samples)
        chosen_password = secrets.choice(password_list)
        logging.info(f"Chosen Password from NIST: {chosen_password}")

    elif entropy_method == "keepassxc":
        # Generating sample passwords for entropy calculation
        sample_passwords = generate_sample_passwords(password_length, num_samples)

        # Calculating and displaying entropy using Keepassxc method
        entropy_values = [calculate_entropy_keepassxc(password) for password in sample_passwords]
        min_entropy = min(entropy_values)
        max_entropy = max(entropy_values)
        average_entropy = sum(entropy_values) / len(entropy_values)

        logging.info(f"Entropy Range: {min_entropy:.2f} - {max_entropy:.2f} bits")
        logging.info(f"Average Entropy: {average_entropy:.2f} bits")

        # Finding the strongest password
        strongest_password = sample_passwords[entropy_values.index(max_entropy)]
        logging.info(f"Password with Highest Entropy: {strongest_password} (Entropy: {max_entropy:.2f} bits)")

        # Using the highest entropy value as requirement
        entropy_requirement = max_entropy

        # Calculating entropy range for the cushion
        min_accepted_entropy = max_entropy - args.cushion

        # Generating passwords meeting the entropy requirement
        non_duplicated_passwords = []
        while len(non_duplicated_passwords) < args.generate:
            password = generate_password(password_length)
            entropy = calculate_entropy_keepassxc(password)
            if min_accepted_entropy <= entropy <= entropy_requirement and password not in non_duplicated_passwords:
                non_duplicated_passwords.append(password)

        # Choosing a password randomly from non-duplicated ones
        if non_duplicated_passwords:
            chosen_password = secrets.choice(non_duplicated_passwords)
            logging.info(f"Chosen Password from Non-Duplicated: {chosen_password} (Entropy: {entropy_requirement:.2f} bits)")
        else:
            logging.warning("No non-duplicated passwords meeting the entropy requirement.")

if __name__ == "__main__":
    main()
