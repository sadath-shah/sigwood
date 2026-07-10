"""Detector plugins. Each module exposes DETECTOR_NAME and run(context) -> list[Finding].

The framework discovers detectors automatically by scanning this package for modules
that define DETECTOR_NAME. No registry file, no import needed here.
"""
