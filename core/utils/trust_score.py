# core/utils/trust_score.py

from decimal import Decimal


def calculate_provider_trust_score(provider):
    """
    Calculate trust score based on 6 profile factors.
    Returns: Integer 0-100
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
    
    # 5. CERTIFICATIONS (15 points)
    try:
        has_certifications = provider.certifications.exists()
    except AttributeError:
        has_certifications = bool(getattr(provider, 'certification', None))
    
    if has_certifications:
        score += 15
    
    # 6. SERVICE PRICES SET (10 points)
    services_offered = provider.service_prices.filter(offered=True).count()
    if services_offered >= 3:
        score += 10
    elif services_offered >= 1:
        score += 6
    
    return min(score, 100)


def get_provider_tier(provider):
    """
    Determine provider's quality tier.
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
    
    trust_score = calculate_provider_trust_score(provider)
    
    if trust_score >= 80:
        return "premium"
    elif trust_score >= 50:
        return "standard"
    else:
        return "budget"


def is_provider_eligible_for_tier(provider, required_tier):
    """
    Check if a provider can accept jobs from a specific tier.
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