import ssl
import socket
import argparse
from urllib.parse import urlparse
import OpenSSL


def fetch_certificate(host, port=443):
    try:
        cert = ssl.get_server_certificate((host,port),timeout=2)
        return(cert)
    except Exception as e:
        print(f"Error fetching certificate for {host}: {e}")
        return None
    

# Function to extract relevant information from the certificate
def extract_certificate_info(cert):
    if not cert:
        return None

    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    issuer = x509.get_issuer().get_components()

    info = ",".join([f"{i[0].decode()}={i[1].decode()}" for i in issuer])
    return info

# Main function to process a list of URLs
def process_urls(urls):
    results = []

    for url in urls:
        parsed_url = urlparse(url)
        host = parsed_url.netloc or parsed_url.path

        if ":" in host:
            host = host.split(":")[0]  # Remove port if present

        print("\nURL:", url)
        cert = fetch_certificate(host)
        if cert:
            cert_info = extract_certificate_info(cert)
            if cert_info:
                color = "\033[0m"
                if "DC=" in cert_info:
                    color = "\033[31m"

                print(f"Issuer: {color}{cert_info}\033[0m")
        else:
            print(f"No certificate found for {url}")

    return results

# Read URLs from a file
def read_urls_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch SSL certificates from a list of URLs or a single URL.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to the file containing URLs")
    group.add_argument("-u", "--url", help="Single URL to process")
    args = parser.parse_args()

    if args.file:
        url_list = read_urls_from_file(args.file)
    elif args.url:
        url_list = [args.url]
    else:
        url_list = []

    if not url_list:
        print("No URLs to process.")
    else:
        cert_results = process_urls(url_list)

