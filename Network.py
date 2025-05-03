import requests

url = "https://httpbin.org/post"
file_path = "D:\\Ziad\\university\\Year 4\\security\\project\\test_folder\\test_upload.txt"

with open(file_path, "wb") as f:
    f.write(b"A" * 60_000_000)  # Create 60MB file

with open(file_path, "rb") as f:
    response = requests.post(url, files={"file": f})
    print("Uploaded:", response.status_code)