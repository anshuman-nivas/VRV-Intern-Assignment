import csv
from collections import *

# Defining the files
LOG_FILE = "sample.log"
CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10


def count_requests_per_ip(log_lines):
    """Counting the number of requests per IP address."""
    ip_counts = defaultdict(int)
    for line in log_lines:
        ip = line.split()[0]
        ip_counts[ip] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)


def find_most_frequent_endpoint(log_lines):
    """Finding the most frequently accessed endpoint."""
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        parts = line.split('"')
        if len(parts) > 1:
            request = parts[1]
            endpoint = request.split()[1]
            endpoint_counts[endpoint] += 1
    most_frequent = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_frequent


def detect_suspicious_activity(log_lines):
    """Detecting suspicious activity based on failed login attempts."""
    failed_login_counts = defaultdict(int)
    for line in log_lines:
        if "401" in line or "Invalid credentials" in line:
            ip = line.split()[0]
            failed_login_counts[ip] += 1
    return {ip: count for ip, count in failed_login_counts.items() if count > FAILED_LOGIN_THRESHOLD}


def save_results_to_csv(ip_counts, most_frequent_endpoint, suspicious_activities):
    """Save the analysis results to a CSV file."""
    with open(CSV_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_frequent_endpoint[0], most_frequent_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activities.items())


def main():
    # Read log file
    try:
        with open(LOG_FILE, "r") as file:
            log_lines = file.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{LOG_FILE}' not found.")
        return

    # Perform analysis
    ip_counts = count_requests_per_ip(log_lines)
    most_frequent_endpoint = find_most_frequent_endpoint(log_lines)
    suspicious_activities = detect_suspicious_activity(log_lines)

    # Display results
    print("Requests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in ip_counts:
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent_endpoint[0]} (Accessed {
          most_frequent_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_frequent_endpoint,
                        suspicious_activities)
    print(f"\nResults saved to '{CSV_FILE}'.")


if __name__ == "__main__":
    main()
