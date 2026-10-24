import base64

import qrcode
from qrcode.image.svg import SvgPathFillImage


def svg_data_uri(data: str) -> str:
    """QR code as an SVG data: URI. The white background keeps it scannable in dark mode."""
    image = qrcode.make(data, image_factory=SvgPathFillImage, box_size=10, border=2)
    return "data:image/svg+xml;base64," + base64.b64encode(image.to_string()).decode("ascii")
