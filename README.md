# Sspamm - Semi's Spam Milter

**Sspamm** (Semi's Spam Milter) is a powerful, flexible, and lightweight Python-based milter designed to filter spam emails using regular expressions (regex) and customizable rules. Built for integration with mail servers like Postfix, Sspamm provides robust anti-spam capabilities through a regex-driven configuration, allowing administrators to define precise filtering rules for domains, headers, and email content. With recent additions like greylisting and JSON-based email logging, Sspamm is both secure and developer-friendly.

## Key Features

- **Regex-Based Filtering**: Define fine-grained rules using regular expressions in a simple `.ini` configuration file to block, greylist, or pass emails based on sender, headers, or content.
- **Greylisting Support**: Temporarily reject emails from unknown senders to deter spammers, with configurable timeouts per rule (e.g., `(?#greylist:600)` for a 10-minute delay).
- **JSON Email Logging**: Safely store email metadata in JSON format (replacing insecure `.var` files) for offline testing and debugging, with proper handling of special characters.
- **Multi-Threaded Design**: Thread-safe processing with efficient configuration reloading and optional locking for shared data structures like the greylist database.
- **Domain-Specific Rules**: Apply different filtering tests (e.g., `ipfromto`, `wordscan`, `headers`) to specific domains or a default policy for unlisted domains.
- **Extensible and Open Source**: Easy to extend with new tests or integrate with mail servers, licensed under [MIT License](#license).

## Installation

### Prerequisites
- Python 3.6+
- `pylibmilter` for milter functionality
- Postfix or another compatible mail server

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Hallikas/sspamm.git
   cd sspamm
   ```
2. Install dependencies:
   ```bash
   pip install pylibmilter
   ```
3. Configure Postfix to use Sspamm:
   - Add to `/etc/postfix/main.cf`:
     ```ini
     smtpd_milters = unix:/var/run/sspamm.sock
     ```
4. Copy the default configuration file:
   ```bash
   cp sspamm.conf.example /etc/sspamm.conf
   ```
5. Start the milter:
   ```bash
   python3 sspamm.py3
   ```

## Configuration

Sspamm uses a `.ini` file (`sspamm.conf`) for configuration. Key sections include:

- **`[main]`**: General settings like `savedir` (e.g., `/data/var`) and `greylist_default` (e.g., `300` seconds).
- **`[domains]`**: Specify tests for domains (e.g., `hallikas.com: accept, date, headers, ipfromto, wordscan`).
- **Test Sections** (e.g., `[ipfromto]`, `[wordscan]`): Define regex rules with actions like `delete` or `greylist`.

### Example Configuration
```ini
[main]
savedir: /data/var
varext: .json
debug: 1
greylist_default: 300

[domains]
default: accept, date, headers, ipfromto
hallikas.com: accept, date, block, headers, ipfromto, wordscan

[ipfromto]
(?#delete)^[a-zA-Z0-9._%+-]+@.+\.icu:.*$
(?#greylist:600)^[a-zA-Z0-9._%+-]+@(?P<domain>.+\.xyz):.*$

[wordscan]
50: (?#delete)\b(pills?|viagra|cialis)\b
10: (?#greylist:300).*(signup|login|verify).*
```

### Greylisting (ToDo feature)
Greylisting temporarily rejects emails from unknown senders with a `450 Try again later` response. For example, emails from `.xyz` domains are greylisted for 600 seconds, while spam keywords like "viagra" trigger immediate deletion.

## Usage

- **Live Filtering**: Sspamm processes incoming emails via the milter interface, applying rules from `sspamm.conf`. Blocked emails are rejected with a `550` response, while greylisted emails return `450`.
- **Offline Testing**: Use the `test` class to analyze saved JSON files (e.g., `00000407.json`) for debugging:
  ```bash
  python3 sspamm.py3 --test /data/var/00000407.json
  ```
- **Logs**: Enable detailed logging (e.g., `debug_ipfromto: 2`) to track rule matches and greylist actions.

## Example
An email from `newsletter@investorvary.today` to `semi@hallikas.com` with subject "Weird 5-second bedroom trick drives women WILD" might be:
- **Greylisted**: If it matches `(?#greylist:600)^[a-zA-Z0-9._%+-]+@.+\.xyz:.*$`, it’s rejected for 600 seconds.
- **Logged**: Saved as `/data/var/00000407.json` with `action: ["greylist"]`.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please include tests and update documentation for new features.

## License

Sspamm is licensed under the [MIT License](LICENSE).

## Contact

For issues or questions, open an issue on GitHub or contact sspamm@hallikas.com.

---

*Last updated: July 26, 2025*
