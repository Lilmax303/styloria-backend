# core/utils/trust_score.py
from decimal import Decimal

def calculate_base_trust_score(provider):
    """
    Calculate base trust score (without service-specific certification bonus).
    Returns: Integer 0-85 (leaves 15 points for service-specific certification)
    """
    score = 0
    user = provider.user
    
    # 1. KYC VERIFICATION (25 points)
    if provider.verification_status == "approved":
        score += 25
    
    # 2. PORTFOLIO MEDIA (20 points)
    from core.models import ProviderPortfolioMedia
    
    try:
        portfolio_count = ProviderPortfolioMedia.objects.filter(
            post__provider=provider
        ).count()
    except Exception:
        portfolio_count = 0
    
    if portfolio_count >= 5:
        score += 20
    elif portfolio_count >= 3:
        score += 15
    elif portfolio_count >= 1:
        score += 8
    
    # 3. BIO COMPLETENESS (15 points)
    bio = provider.bio or ""
    bio_length = len(bio.strip())
    
    if bio_length >= 150:
        score += 15
    elif bio_length >= 80:
        score += 10
    elif bio_length >= 30:
        score += 5
    
    # 4. PROFILE PICTURE (15 points)
    has_profile_picture = bool(user.profile_picture)
    if has_profile_picture:
        score += 15
    
    # 5. SERVICE PRICES SET (10 points)
    services_offered = provider.service_prices.filter(offered=True).count()
    if services_offered >= 3:
        score += 10
    elif services_offered >= 1:
        score += 6
    
    return min(score, 85)  # Max 85, leaving 15 for certification


def has_verified_cert_for_service(provider, service_type: str) -> bool:
    """
    Check if provider has a verified certification for a specific service.
    Uses explicit service linking (not keyword matching).
    """
    try:
        return provider.certifications.filter(
            is_verified=True,
            certified_service_types__contains=[service_type]
        ).exists()
    except AttributeError:
        # Fallback for old certification field
        return False


def calculate_provider_trust_score_for_service(provider, service_type: str):
    """
    Calculate trust score for a specific service.
    
    This is the NEW per-service trust score that gives certification bonus
    ONLY if the provider has a verified cert for THAT specific service.
    
    Returns: Integer 0-100
    """
    # Start with base score (KYC, portfolio, bio, pic, services)
    score = calculate_base_trust_score(provider)
    
    # Add certification bonus ONLY if cert exists for THIS service
    if has_verified_cert_for_service(provider, service_type):
        score += 15
    
    return min(score, 100)


def calculate_provider_trust_score(provider):
    """
    Calculate GLOBAL trust score (for backward compatibility).
    
    This gives the certification bonus if provider has ANY verified cert.
    Used for general profile display where service context doesn't matter.
    
    Returns: Integer 0-100
    """
    score = calculate_base_trust_score(provider)
    
    # Add certification bonus if provider has ANY verified cert
    try:
        has_any_cert = provider.certifications.filter(is_verified=True).exists()
    except AttributeError:
        has_any_cert = bool(getattr(provider, 'certification', None))
    
    if has_any_cert:
        score += 15
    
    return min(score, 100)


def get_provider_tier(provider):
    """
    Determine provider's quality tier (GLOBAL - not service-specific).
    Returns: 'budget', 'standard', or 'premium'
    """
    jobs_completed = getattr(provider, 'completed_jobs_count', 0) or 0
    avg_rating = getattr(provider, 'average_rating', None)
    
    if jobs_completed >= 10 and avg_rating is not None:
        if jobs_completed >= 50 and avg_rating >= 4.5:
            return "premium"
        elif jobs_completed >= 20 and avg_rating >= 4.0:
            return "standard"
        else:
            return "budget"
    
    # Use global trust score for tier calculation
    trust_score = calculate_provider_trust_score(provider)
    
    if trust_score >= 80:
        return "premium"
    elif trust_score >= 50:
        return "standard"
    else:
        return "budget"


def get_provider_tier_for_service(provider, service_type: str):
    """
    Determine provider's quality tier FOR A SPECIFIC SERVICE.
    
    This is the NEW per-service tier calculation that considers:
    - Whether provider has certification for THIS service
    - Their performance stats
    
    Returns: 'budget', 'standard', or 'premium'
    """
    jobs_completed = getattr(provider, 'completed_jobs_count', 0) or 0
    avg_rating = getattr(provider, 'average_rating', None)
    
    # If enough jobs done, use performance-based tier
    if jobs_completed >= 10 and avg_rating is not None:
        if jobs_completed >= 50 and avg_rating >= 4.5:
            return "premium"
        elif jobs_completed >= 20 and avg_rating >= 4.0:
            return "standard"
        else:
            return "budget"
    
    # Otherwise use service-specific trust score
    trust_score = calculate_provider_trust_score_for_service(provider, service_type)
    
    if trust_score >= 80:
        return "premium"
    elif trust_score >= 50:
        return "standard"
    else:
        return "budget"


def is_provider_eligible_for_tier(provider, required_tier):
    """
    Check if a provider can accept jobs from a specific tier (GLOBAL).
    """
    provider_tier = get_provider_tier(provider)
    
    tier_hierarchy = {
        'premium': 3,
        'standard': 2,
        'budget': 1,
    }
    
    provider_level = tier_hierarchy.get(provider_tier, 1)
    required_level = tier_hierarchy.get(required_tier, 1)
    
    return provider_level >= required_level


def is_provider_eligible_for_tier_and_service(provider, required_tier, service_type: str):
    """
    Check if provider can accept jobs from a specific tier FOR A SPECIFIC SERVICE.
    
    This is the NEW per-service tier check.
    """
    provider_tier = get_provider_tier_for_service(provider, service_type)
    
    tier_hierarchy = {
        'premium': 3,
        'standard': 2,
        'budget': 1,
    }
    
    provider_level = tier_hierarchy.get(provider_tier, 1)
    required_level = tier_hierarchy.get(required_tier, 1)
    
    return provider_level >= required_level


def get_eligible_tiers(provider_tier):
    """
    Return list of tiers a provider can accept jobs from.
    """
    if provider_tier == 'premium':
        return ['budget', 'standard', 'premium']
    elif provider_tier == 'standard':
        return ['budget', 'standard']
    else:
        return ['budget']