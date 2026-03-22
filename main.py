from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class URLRequest(BaseModel):
    url: str

def check_phishing(url: str):
    score = 0
    reasons = []

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 30
        reasons.append("Uses IP address")

    if "@" in url:
        score += 20
        reasons.append("It Contains @ symbol")

    if len(url) > 75:
        score += 20
        reasons.append("URL too long")

    if url.count('-') > 3:
        score += 15
        reasons.append("Too many hyphens")

    if score < 30:
        result = "SAFE"
    elif score < 70:
        result = "SUSPICIOUS"
    else:
        result = "PHISHING"

    return result, score, reasons


@app.post("/check")
def check_url(data: URLRequest):
    result, score, reasons = check_phishing(data.url)

    return {
        "result": result,
        "score": score,
        "reasons": reasons
    }