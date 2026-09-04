from pydantic import BaseModel

from app.ai.ai_text_detection import AiTextScore
from app.ai.lookalike_domain import LookalikeAnalysis
from app.ai.phishing_classifier import PhishingClassification
from app.ai.url_analysis import UrlAnalysis


class AiSignals(BaseModel):
    sender_domain_lookalike: LookalikeAnalysis | None = None
    urls: UrlAnalysis
    phishing: PhishingClassification
    ai_text: AiTextScore
