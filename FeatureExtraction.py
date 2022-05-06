import pandas as pd
from urllib.parse import urlparse
import re

dataphish = pd.read_csv('phishing_dataset.csv')
dataphish.columns = ['URLs']

dp = dataphish.sample(n=5000, random_state=12).copy()
dp = dp.reset_index(drop=True)

datalegitimate = pd.read_csv("legitimate_dataset.csv")
datalegitimate.columns = ['URLs']

dl = datalegitimate.sample(n=5000, random_state=12).copy()
dl = dl.reset_index(drop=True)


def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


def haveAtSign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at


def length(url):
    if len(url) < 54:
        urllength = 0
    else:
        urllength = 1
    return urllength


def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0


def featureExtraction(url, label):
    features = [getDomain(url), getDepth(url), haveAtSign(url), length(url), redirection(url), httpDomain(url),
                tinyURL(url), prefixSuffix(url), label]

    return features


legitimate_features = []
label = 0
for i in range(0, 5000):
    url = dl['URLs'][i]
    legitimate_features.append(featureExtraction(url, label))

feature_names = ['Domain_Name', 'URL_Depth', 'Have_At', 'URL_Length', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'Label']

legitimate = pd.DataFrame(legitimate_features, columns=feature_names)

legitimate.to_csv('legitimate.csv', index=False)

phishing_features = []
label = 1
for i in range(0, 5000):
    url = dp['URLs'][i]
    phishing_features.append(featureExtraction(url, label))

phishing = pd.DataFrame(phishing_features, columns=feature_names)

phishing.to_csv('phishing.csv', index=False)

urls = pd.concat([legitimate, phishing]).reset_index(drop=True)

urls.to_csv('Classified_Dataset.csv', index=False)