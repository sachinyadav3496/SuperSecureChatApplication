#!/usr/bin/env python3
import board as bd
import digitalio as dio
import adafruit_matrixkeypad as mat_keypad
import time

col_pins = [bd.D26, bd.D19, bd.D13, bd.D6]
row_pins = [bd.D21, bd.D20, bd.D16, bd.D12]

rows = []
cols = []

for row_pin in row_pins:
    rows.append(dio.DigitalInOut(row_pin))

for col_pin in col_pins:
    cols.append(dio.DigitalInOut(col_pin))

keys = (
        ("D", "#", 0, "*"),
        ("C", 9,   8,  7),
        ("B", 6,   5,  4),
        ("A", 3,   2,   1)
        )
keypad = mat_keypad.Matrix_Keypad(rows, cols, keys)

while True:
    kp = keypad.pressed_keys
    if kp:
        print(f"Pressed : {kp}")
    time.sleep(0.2)
