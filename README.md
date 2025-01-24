# Instagram API Automation

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A Python-based tool for automating interactions with Instagram's private API. This repository allows you to log in, post comments, explore posts, and search for content programmatically. It mimics the behavior of the Instagram mobile app, enabling tasks such as engagement automation, data collection, and account management.

---

## Features

- **Login Automation**: Log in to Instagram using a username and password. Encrypts the password using Instagram's public key.
- **Comment Automation**: Post comments on Instagram posts with secure HMAC signatures.
- **Explore and Search Automation**: Automatically explore posts and search for content based on keywords.
- **Session Management**: Save session data (e.g., authorization tokens, device IDs) for seamless resumption.
- **Error Handling**: Robust error handling for failed requests, decompression errors, and JSON parsing.
- **Compression Handling**: Supports decompression of API responses (zstd, gzip, deflate).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Instagram-API-Automation.git
   cd Instagram-API-Automation
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up your credentials:
   Replace `your_username` and `your_password` in the script with your Instagram credentials.

---

## Usage

### Logging In
```python
from instagram_automation import login

# Log in to Instagram
lg = login("your_username", "your_password")
print(lg)
```

### Posting a Comment
```python
from instagram_automation import comment

# Post a comment on a specific post
comment(lg["IG-Set-Authorization"], "post_id", "Your comment here", lg["accountId"], lg["deviceUid"], lg["uuid"])
```

### Exploring Posts
```python
from instagram_automation import explore

# Explore posts and comment on them
explore(lg["IG-Set-Authorization"], lg["accountId"], lg["deviceUid"])
```

### Searching for Posts
```python
from instagram_automation import explorebySearch

# Search for posts and comment on them
explorebySearch(lg["uuid"], lg["IG-Set-Authorization"], lg["accountId"], lg["deviceUid"], "search_term")
```

---

## Important Notes

- **Ethical Use**: Use this tool responsibly and in compliance with Instagram's terms of service. Misuse (e.g., spamming) can lead to account bans.
- **Rate Limiting**: The script includes random delays between actions to avoid triggering Instagram's rate limits or anti-bot mechanisms.
- **Security**: Avoid hardcoding sensitive information (e.g., passwords) in the script. Use environment variables or secure storage for credentials.

---

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Disclaimer

This project is for educational purposes only. The authors are not responsible for any misuse of this tool. Use it at your own risk.

---

## `requirements.txt`

```plaintext
requests==2.31.0
tls-client==0.1.7
cryptography==41.0.3
zstandard==0.21.0
```

---

## LICENSE

```plaintext
MIT License

Copyright (c) 2025 AKRAM ELBAHAR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
