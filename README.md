# cert_check

A small tool to identify internal domains from certificate issuers.

## Help

```
$ python3 cert_check.py -h                       
usage: cert_check.py [-h] (-f FILE | -u URL)

Fetch SSL certificates from a list of URLs or a single URL.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the file containing URLs
  -u URL, --url URL     Single URL to process
```

