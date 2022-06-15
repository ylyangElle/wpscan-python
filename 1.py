import requests
session = requests.Session()
payloadUrl = urljoin(baseUrl, 'index.php?activate=1')
session.get(payloadUrl)