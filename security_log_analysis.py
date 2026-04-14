import pandas as pd
import matplotlib.pyplot as plt
from sklearn.neighbors import LocalOutlierFactor

df = pd.read_csv("security_auth_logs.csv")


df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour


df["status"] = df["status"].str.upper().str.strip()
df["failed"] = (df["status"] == "FAILED").astype(int)


features = df.groupby(["source_ip", "hour"]).agg(
    failed_attempts=("failed", "sum"),
    total_attempts=("status", "count")
).reset_index()

features["fail_ratio"] = features["failed_attempts"] / features["total_attempts"]
model = LocalOutlierFactor(n_neighbors=20, contamination=0.05)

features["anomaly"] = model.fit_predict(
    features[["failed_attempts", "total_attempts", "fail_ratio"]]
)


anomalies = features[features["anomaly"] == -1]

print("Обнаруженные подозрительные IP:")
print(anomalies.sort_values("failed_attempts", ascending=False))


fails_per_hour = df[df["failed"] == 1].groupby("hour").size()

plt.figure()
fails_per_hour.plot(kind="bar")
plt.title("Failed logins per hour")
plt.xlabel("Hour")
plt.ylabel("Number of failed logins")
plt.show()

top_ips = df[df["failed"] == 1]["source_ip"].value_counts().head(5)

plt.figure()
top_ips.plot(kind="bar")
plt.title("Top attacking IP addresses")
plt.xlabel("IP address")
plt.ylabel("Failed attempts")
plt.show()


night_logins = df[df["hour"].between(2, 5)]

print("\nЛогины в необычные часы (2–5 AM):")
print(night_logins[["timestamp", "username", "source_ip", "country", "status"]])
