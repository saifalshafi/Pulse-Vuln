from setuptools import setup, find_packages

setup(
    name="pulse-sec",
    version="1.0.0",
    author="Cyber Defense Research Team",
    description="PULSE - Enterprise Vulnerability Intelligence Engine",
    packages=find_packages(),
    install_requires=[
        "requests",
        "reportlab",
        "PyQt6",
        "PyQt6-Charts"
    ],
    entry_points={
        "console_scripts": [
            "pulse=scanner_app.main:main",
        ]
    },
    python_requires=">=3.9",
)
