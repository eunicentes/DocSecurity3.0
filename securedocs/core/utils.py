# core/utils.py
import cv2

def decode_qr_opencv(image_path):
    detector = cv2.QRCodeDetector()
    image = cv2.imread(image_path)
    if image is None:
        return None
    data, bbox, _ = detector.detectAndDecode(image)
    return data if data else None
