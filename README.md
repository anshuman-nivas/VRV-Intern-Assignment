# VRV-Intern-Assignment

This Python script is my submission for the VRV Security intern assignment. It processes a log file (sample.log) to extract useful information like the number of requests from each IP address, the most frequently accessed endpoint, and any suspicious activity like potential brute force login attempts.

Requests per IP Address:
The script parses the log file to identify all IP addresses and count how many requests each one made. The results are sorted in descending order to highlight the most active IPs.

Most Accessed Endpoint:
It analyzes the logs to find the most frequently accessed endpoint (like /home or /login) and shows how many times it was accessed.

Suspicious Activity Detection:
The script flags IPs with too many failed login attempts (by default, more than 10) to help identify suspicious activity, like brute force attacks.

Output:
The results are shown in the terminal as well as saved in a CSV file (log_analysis_results.csv) for easy reference.
