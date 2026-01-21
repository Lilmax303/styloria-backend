from django.test import TestCase

# test_currency_import.py
import sys
sys.path.insert(0, r'C:\Users\kwame\styloria\styloria_project')

try:
    from core.utils.currency import convert_amount
    print("✓ Currency import successful!")
    print(f"Test: 100 USD to GHS = {convert_amount(100, 'USD', 'GHS')}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()