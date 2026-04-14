# Security Log Analysis

## Description
This project analyzes authentication logs to detect suspicious login activity using Python.

## Features
- Detection of failed login attempts
- Identification of suspicious IP addresses
- Analysis of login activity by time
- Visualization of security data
- Basic anomaly detection using Local Outlier Factor (LOF)

## Technologies
- Python
- Pandas
- Matplotlib
- Scikit-learn

## Dataset
Sample dataset: `security_auth_logs.csv`

## How it works
- Parses authentication logs from a CSV file
- Extracts time-based features (e.g., login hour)
- Calculates failed login ratios
- Applies anomaly detection (LOF)
- Identifies suspicious behavior patterns

## Output
- Top attacking IP addresses
- Failed logins per hour
- Suspicious login activity
- Visual charts

## Project Goal
To demonstrate basic security log analysis and anomaly detection techniques.
