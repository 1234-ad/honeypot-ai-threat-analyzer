#!/usr/bin/env python3
"""
Setup script for Honeypot AI Threat Analyzer
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="honeypot-ai-threat-analyzer",
    version="1.0.0",
    author="Cybersecurity Researcher",
    author_email="security@example.com",
    description="AI-powered honeypot network that captures, analyzes, and predicts cybersecurity threats",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/1234-ad/honeypot-ai-threat-analyzer",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.2",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.1",
        ],
        "monitoring": [
            "prometheus-client>=0.17.1",
            "grafana-api>=1.0.3",
        ],
        "threat-intel": [
            "yara-python>=4.3.1",
            "virustotal-api>=1.1.11",
            "shodan>=1.29.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "honeypot-analyzer=main:main",
            "honeypot-dashboard=dashboard.app:main",
            "honeypot-train=ai.train_models:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "config/*.yaml",
            "dashboard/templates/*.html",
            "dashboard/static/*",
            "models/*.pkl",
        ],
    },
    zip_safe=False,
    keywords=[
        "cybersecurity",
        "honeypot",
        "threat-intelligence",
        "machine-learning",
        "network-security",
        "intrusion-detection",
        "ai",
        "security-monitoring",
    ],
    project_urls={
        "Bug Reports": "https://github.com/1234-ad/honeypot-ai-threat-analyzer/issues",
        "Source": "https://github.com/1234-ad/honeypot-ai-threat-analyzer",
        "Documentation": "https://github.com/1234-ad/honeypot-ai-threat-analyzer/wiki",
    },
)