# core/utils/regions.py

AFRICAN_COUNTRIES = {
    "Algeria","Angola","Benin","Botswana","Burkina Faso","Burundi","Cabo Verde",
    "Cameroon","Central African Republic","Chad","Comoros","Congo",
    "Democratic Republic of the Congo","Djibouti","Egypt","Equatorial Guinea",
    "Eritrea","Eswatini","Ethiopia","Gabon","Gambia","Ghana","Guinea",
    "Guinea-Bissau","Côte d’Ivoire","Cote d'Ivoire","Ivory Coast","Kenya",
    "Lesotho","Liberia","Libya","Madagascar","Malawi","Mali","Mauritania",
    "Mauritius","Morocco","Mozambique","Namibia","Niger","Nigeria","Rwanda",
    "Sao Tome and Principe","Senegal","Seychelles","Sierra Leone","Somalia",
    "South Africa","South Sudan","Sudan","Tanzania","Togo","Tunisia","Uganda",
    "Zambia","Zimbabwe",
}

def _norm(s: str) -> str:
    return (
        (s or "")
        .strip()
        .replace("’", "'")
        .lower()
    )

def is_african_country_name(country_name: str | None) -> bool:
    if not country_name:
        return False
    n = _norm(country_name)
    return n in {_norm(c) for c in AFRICAN_COUNTRIES}

def parse_stripe_allowed_african_countries(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {c.strip() for c in raw.split(",") if c.strip()}