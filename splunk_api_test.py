
import requests
import getpass
import urllib3

urllib3.disable_warnings()

username = input("Splunk username: ")
password = getpass.getpass("Splunk password: ")

url = "https://192.168.64.9:8089/services/server/info"

try:
    response = requests.get(
        url,
        auth=(username, password),
        params={"output_mode": "json"},
        verify=False,
        timeout=10
    )

    print("\nHTTP Status:", response.status_code)

    if response.status_code == 200:
        data = response.json()
        print("API Connection: SUCCESS")
        print("Splunk Server:", data["entry"][0]["content"]["serverName"])
        print("Splunk Version:", data["entry"][0]["content"]["version"])
    else:
        print("API Connection: FAILED")
        print(response.text[:500])

except requests.exceptions.RequestException as error:
    print("Connection Error:", error)

