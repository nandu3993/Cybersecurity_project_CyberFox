from PIL import Image
import numpy as np
import os
import datetime
import random,string
from itertools import product
import hashlib
from PyQt5.QtCore import QThread, pyqtSignal
def detect_steganography(image_path, threshold=0.1):
    try:
        image = Image.open(image_path)
        pixels = np.array(image)
        # Extract the least significant bits
        lsb_values = pixels & 1
        # Calculate the percentage of non-zero LSB values
        non_zero_percentage = np.count_nonzero(lsb_values) / lsb_values.size
        if non_zero_percentage > threshold:
            return True
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False

def pngfileinfo(imagepath):
    try:
        file_info = os.stat(imagepath)
        creation_time = file_info.st_ctime
        modification_time = file_info.st_mtime
        creation_date = str(datetime.datetime.fromtimestamp(creation_time))
        modification_date = str(datetime.datetime.fromtimestamp(modification_time))
        with Image.open(imagepath) as img:
            # Basic information
            width, height = img.size
            mode = img.mode
            palette = img.getpalette()
            transparency = img.info.get('transparency', None)
            gamma = img.info.get('gamma', None)
            dpi = img.info.get('dpi', None)
            png_info = {
                "Width": width,
                "Height": height,
                "Color Mode": mode,
                "Creation Date": creation_date,
                "Modification Date": modification_date,
                "Palette": palette,
                "Transparency": transparency,
                "Gamma": gamma,
                "DPI": dpi
            }

            return png_info

    except Exception as e:
        # Handle errors
        return {"Error": str(e)}
def generate_passwords(words):
    if not words:
        return "Please enter at least one word."

    all_combinations = []

    for r in range(1, len(words) + 1):
        combinations = product(words, repeat=r)
        for combination in combinations:
            compact_combination = ''.join(combination)
            compact_combination = compact_combination.replace('@', '')
            # Ensure the password doesn't start with a number
            compact_combination = ensure_no_starting_digit(compact_combination)
            all_combinations.append(compact_combination)

    return all_combinations

def ensure_no_starting_digit(password):
    if password and password[0].isdigit():
        return random.choice(string.ascii_letters) + password[1:]
    return password





