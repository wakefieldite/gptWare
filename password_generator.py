"""
This code was made to attempt to make a strong password generator.
Normally, I use KeepassXC to generate strong passwords and I spent quite a bit of time clicking and trying to find the strongest password it can generate.
Due to the amount of passwords you need to generate to get back to a password you accidentally clicked past because prior to it you got passwords that were weaker, you may want to automate searching for the stongest password you can make.
I started without KeepassXC, because the omniscient ChatGPT didn't know you could just use keepassxc-cli to estimate the entropy of a password.
So I started out doing just random stuff and eventually found out about methods of entropy calculation, this now becomes a lesson.

Before we get started, I must advise that this isn't necessarily a good security practice if you believe in security through obscurity.
The reason I say that is, as I will demonstrate, only using the strongest of passphrases based on some models significantly reduces the potential passphrases yours could be.
If your threat model includes adversaries that are aware of your password hygiene habits, this would enable them to generate passwords meeting the criteria established by your password generation behavior.
This means, if I generate passwords using keepass that are n length and x bits of entropy, your adversary just needs to generate a list of passwords that are n length and x bits of entropy according to the model you use.
From there, the adversary would just use those passwords as their wordlist when trying to bruteforce access into whatever you are guarding with a passphrase.

Additionally, if your anonymity matters to you then your password hygiene behaviors would be used to identify you if passwords are found in plaintext.
The goal of anonymity is to blend in on the internet, not stand out because you have the strongest password or most hardened web browser configuration.
This is why we advocate for using the Tor browser to reduce uniqueness, hardened browsers make you stand out while if everyone used the same browser configuration then browser fingerprinting would be less effective.
A bit off topic there is currently the new Rowhammer attack that will uniquely identify hardware and I'm not sure if Tor Browser has any measures against that currently, if you're someone who relies on Tor for anonymity, you may want to look into that.
https://arxiv.org/pdf/2307.00143.pdf

Back to the lesson now, let's talk about how this program works.

The arguments are as follow:
    --length: No default value is specified, so it's a required argument.
    --samples: Default value is 1000
    --method: Default value is "shannon".
        - options are shannon, nist, or keepassxc
    --cushion: Default value is 3.0.
        - only used by keepassxc method
    --generate: Default value is 50.
        - only used by keepassxc method, shannon uses the --sample value instead due to issues with duplicates
Character set is hardcoded to azAZ09 and punctuation.

Entropy calculation is problem with this program:

NIST method: all passwords of the keyspace aka (length * count(character set)) have the same strength.

KeepassXC method: other factors come into play, for example the word "password" is scored as 1 bit of entropy while using "passwor" is actually 9.99 bits of entropy, "Password" is 2 bits of entropy, "P@55w0rd" has 3.58 bits of entropy.
Another example would be keyboard walking, "1qaz" is 10.34 bits, "1qaz2" is 16.51 bits, and yet "1qaz2w" is 13.86 bits, and by the time you make it to "1qaz2wsx" it is down to 4.81 bits which is less than half of the 4 characters we started out with.
In other words, KeepassXC factors in bad password hygiene when deciding on the strength of the passphrase.

Now, the Shannon method is a bit more complex so I'll let ChatGPT explain a bit:

The Shannon entropy method calculates the entropy of a password by analyzing the distribution of characters within the password.
It quantifies the uncertainty or randomness present in the password based on the frequency of each character.

Here's a concise explanation of how the Shannon entropy method works:
1. Calculate Character Frequencies: The method starts by counting the occurrences of each unique character in the password.
2. Compute Probabilities: For each character, calculate its probability of occurrence by dividing the count of that character by the total password length.
3. Entropy Calculation: Calculate the entropy for each character using the formula:
    Entropy = - Σ (probability_n * log2(probability_n))
4. Where probability_n is the probability of occurrence of the n-th character.
5. Sum Up Entropies: Sum up the calculated entropies for all characters in the password to get the overall entropy value.
6. Interpretation: A higher entropy value indicates greater randomness and unpredictability, which implies a stronger password.

In essence, the Shannon entropy method measures how evenly characters are distributed in a password.
Passwords with a more balanced distribution of characters across the character set will have higher entropy values, making them more resistant to various attacks like brute force or dictionary attacks.

Now that we've talked about the entropy methods, let me explain the process this code goes through.

NIST:
1. Generate an array of x sample size of passwords of y length
2. Randomly select a password from that array of passwords.

Shannon:
1. Generates sample passwords meeting length criteria
2. Calculates min, max, and average entropy of the samples.
3. Sets max entropy as requirement.
4. Creates array of non-duplicated passwords meeting the requirement.
5. Logs total duplicates and most common password.
6. If possible, chooses a random high-entropy password that was not found in the list of duplicates
7. If none meet the requirement, logs a warning.

"""
#!/usr/bin/python3
import string
import secrets
import math
import argparse
import logging
import collections
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
        logging.info("Generating sample passwords for entropy calculation...")

        password_list = generate_sample_passwords(password_length, num_samples)
        max_entropy = calculate_and_display_entropy(password_list)  # Calculate the max entropy requirement

        eligible_passwords = []  # Initialize a list to store eligible passwords

        for password in password_list:
            entropy = calculate_entropy_shannon(password)

            if entropy >= max_entropy:
                eligible_passwords.append((password, entropy))

        if eligible_passwords:
            logging.info(f"Generated {len(eligible_passwords)} passwords meeting the entropy requirement.")

            # Calculate the max entropy requirement based on the generated passwords
            max_entropy = calculate_and_display_entropy([password for password, _ in eligible_passwords])

            logging.info("Generating passwords meeting the entropy requirement...")

            non_duplicated_passwords = []
            password_counts = collections.Counter(password_list)

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
                selected_password_entropy = calculate_entropy_shannon(selected_password)
                logging.info(f"Chosen Password from Non-Duplicated: {selected_password} (Entropy: {selected_password_entropy:.2f} bits)")
            else:
                logging.warning("No non-duplicated passwords meeting the entropy requirement.")
        else:
            logging.warning("No passwords meeting the entropy requirement.")

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

