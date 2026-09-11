"""Asset Classifier — classifies assets by type, technology, and risk.

Analyzes discovered assets to:
- Identify asset types (API, admin, staging, etc.)
- Detect technologies and frameworks
- Identify cloud providers and CDNs
- Calculate risk scores
"""

from __future__ import annotations

import re
from typing import Any
from .database import Asset, AssetType, ScopeStatus


# Technology detection patterns
TECH_PATTERNS = {
    "nginx": [r"nginx", r"Server: nginx"],
    "apache": [r"apache", r"Server: Apache"],
    "cloudflare": [r"cloudflare", r"cf-ray"],
    "aws": [r"amazon", r"aws", r"cloudfront", r"amazons3"],
    "gcp": [r"google", r"gcloud", r"google-appengine"],
    "azure": [r"microsoft", r"azure", r"windowsazure"],
    "fastapi": [r"fastapi", r"uvicorn"],
    "django": [r"django", r"csrfmiddleware"],
    "flask": [r"flask", r"Werkzeug"],
    "express": [r"express", r"X-Powered-By: Express"],
    "nextjs": [r"next", r"__NEXT_DATA__"],
    "react": [r"react", r"_reactRoot"],
    "angular": [r"angular", r"ng-version"],
    "vue": [r"vue", r"Vue.js"],
    "laravel": [r"laravel", r"laravel_session"],
    "rails": [r"rails", r"ruby"],
    "spring": [r"spring", r"Spring"],
    "graphql": [r"graphql", r"graphiql"],
    "swagger": [r"swagger", r"openapi"],
    "jwt": [r"jwt", r"Bearer"],
    "oauth": [r"oauth", r"authorization_code"],
    "saml": [r"saml", r"SAMLResponse"],
}

# Risk indicators
RISK_INDICATORS = {
    "admin_panel": [r"admin", r"dashboard", r"console", r"manage"],
    "api_endpoint": [r"/api/", r"/v1/", r"/v2/", r"graphql"],
    "authentication": [r"login", r"auth", r"signin", r"oauth"],
    "sensitive_data": [r"password", r"secret", r"token", r"key"],
    "file_upload": [r"upload", r"file", r"image"],
    "database": [r"mysql", r"postgres", r"mongodb", r"redis"],
    "debug_mode": [r"debug", r"trace", r"stack"],
    "staging": [r"staging", r"stage", r"dev", r"test", r"sandbox"],
}


class AssetClassifier:
    """Classifies assets by type, technology, and risk.

    Usage:
        classifier = AssetClassifier()
        classifier.classify_asset(asset)
        risk_score = classifier.calculate_risk(asset)
    """

    def classify_asset(self, asset: Asset) -> Asset:
        """Classify an asset based on its metadata."""
        # Detect technologies
        if not asset.technologies:
            asset.technologies = self._detect_technologies(asset)

        # Detect framework
        if not asset.framework:
            asset.framework = self._detect_framework(asset)

        # Detect cloud provider
        if not asset.cloud_provider:
            asset.cloud_provider = self._detect_cloud(asset)

        # Detect CDN
        if not asset.cdn:
            asset.cdn = self._detect_cdn(asset)

        # Calculate risk score
        asset.risk_score = self.calculate_risk(asset)

        return asset

    def _detect_technologies(self, asset: Asset) -> list[str]:
        """Detect technologies from metadata."""
        technologies = []
        text = f"{asset.title} {asset.framework} {asset.cdn} {asset.waf}".lower()

        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    technologies.append(tech)
                    break

        return technologies

    def _detect_framework(self, asset: Asset) -> str:
        """Detect the primary framework."""
        frameworks = ["fastapi", "django", "flask", "express", "nextjs",
                      "angular", "vue", "laravel", "rails", "spring"]

        for framework in frameworks:
            if framework in asset.technologies:
                return framework

        return ""

    def _detect_cloud(self, asset: Asset) -> str:
        """Detect cloud provider."""
        if "aws" in asset.technologies or "cloudfront" in asset.technologies:
            return "aws"
        elif "gcp" in asset.technologies:
            return "gcp"
        elif "azure" in asset.technologies:
            return "azure"
        return ""

    def _detect_cdn(self, asset: Asset) -> str:
        """Detect CDN."""
        if "cloudflare" in asset.technologies:
            return "cloudflare"
        elif "cloudfront" in asset.technologies:
            return "cloudfront"
        elif "akamai" in asset.technologies:
            return "akamai"
        elif "fastly" in asset.technologies:
            return "fastly"
        return ""

    def calculate_risk(self, asset: Asset) -> float:
        """Calculate a risk score for an asset (0.0 to 1.0).

        Higher score = higher risk = more interesting to test.
        """
        score = 0.0
        text = f"{asset.hostname} {asset.title} {' '.join(asset.technologies)}".lower()

        # Admin panels are high risk
        for pattern in RISK_INDICATORS["admin_panel"]:
            if re.search(pattern, text):
                score += 0.3
                break

        # API endpoints are interesting
        for pattern in RISK_INDICATORS["api_endpoint"]:
            if re.search(pattern, text):
                score += 0.2
                break

        # Authentication endpoints
        for pattern in RISK_INDICATORS["authentication"]:
            if re.search(pattern, text):
                score += 0.15
                break

        # Staging/dev environments are risky
        for pattern in RISK_INDICATORS["staging"]:
            if re.search(pattern, text):
                score += 0.25
                break

        # Debug mode
        for pattern in RISK_INDICATORS["debug_mode"]:
            if re.search(pattern, text):
                score += 0.2
                break

        # Open ports increase risk
        if asset.ports:
            score += min(len(asset.ports) * 0.02, 0.15)

        # Unknown technologies increase risk
        if not asset.technologies:
            score += 0.05

        return min(score, 1.0)

    def classify_all(self, assets: list[Asset]) -> list[Asset]:
        """Classify all assets."""
        return [self.classify_asset(asset) for asset in assets]
