# core/constants.py

SERVICE_PRICING_GUIDE = {
    'haircut': {
        'minimum': Decimal("15.00"),
        'suggested_range': (Decimal("20.00"), Decimal("60.00")),
        'premium_threshold': Decimal("80.00"),
        'description': "Basic haircuts typically $20-35, styled cuts $35-60",
    },
    'hair_coloring': {
        'minimum': Decimal("40.00"),
        'suggested_range': (Decimal("50.00"), Decimal("150.00")),
        'premium_threshold': Decimal("200.00"),
        'description': "Single process $50-80, highlights $80-150",
    },
    'braiding': {
        'minimum': Decimal("30.00"),
        'suggested_range': (Decimal("50.00"), Decimal("200.00")),
        'premium_threshold': Decimal("300.00"),
        'description': "Simple braids $50-100, complex styles $100-200+",
    },
    'makeup': {
        'minimum': Decimal("25.00"),
        'suggested_range': (Decimal("40.00"), Decimal("120.00")),
        'premium_threshold': Decimal("150.00"),
        'description': "Day makeup $40-60, event/bridal $80-120+",
    },
    'nails': {
        'minimum': Decimal("20.00"),
        'suggested_range': (Decimal("30.00"), Decimal("80.00")),
        'premium_threshold': Decimal("100.00"),
        'description': "Basic manicure $30-45, gel/acrylics $50-80",
    },
    'massage': {
        'minimum': Decimal("40.00"),
        'suggested_range': (Decimal("60.00"), Decimal("120.00")),
        'premium_threshold': Decimal("150.00"),
        'description': "30min $40-60, 60min $80-120",
    },
    'facial': {
        'minimum': Decimal("35.00"),
        'suggested_range': (Decimal("50.00"), Decimal("120.00")),
        'premium_threshold': Decimal("150.00"),
        'description': "Basic facial $50-70, premium treatments $80-120",
    },
    'lashes': {
        'minimum': Decimal("30.00"),
        'suggested_range': (Decimal("50.00"), Decimal("150.00")),
        'premium_threshold': Decimal("200.00"),
        'description': "Classic lashes $50-80, volume $100-150",
    },
    'waxing': {
        'minimum': Decimal("15.00"),
        'suggested_range': (Decimal("25.00"), Decimal("80.00")),
        'premium_threshold': Decimal("100.00"),
        'description': "Single area $25-40, full body $60-80",
    },
    'barber': {
        'minimum': Decimal("15.00"),
        'suggested_range': (Decimal("20.00"), Decimal("50.00")),
        'premium_threshold': Decimal("70.00"),
        'description': "Basic cut $20-30, fade/design $35-50",
    },
}