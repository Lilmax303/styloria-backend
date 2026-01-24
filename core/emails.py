# core/emails.py

import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


def _send_html_email(to_email: str, subject: str, html_content: str, plain_content: str) -> bool:
    """
    Send HTML email via SendGrid HTTP API.
    Falls back gracefully if SendGrid is not configured.
    """
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail, Email, To, Content
        
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            logger.error("SENDGRID_API_KEY not set - cannot send email")
            return False
        
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@styloria.app')
        
        sg = SendGridAPIClient(api_key)
        
        mail = Mail(
            from_email=Email(from_email),
            to_emails=To(to_email),
            subject=subject,
        )
        
        # Add plain text content
        mail.add_content(Content("text/plain", plain_content))
        # Add HTML content
        mail.add_content(Content("text/html", html_content))
        
        response = sg.send(mail)
        
        logger.info(f"Email sent to {to_email}, status: {response.status_code}")
        return response.status_code in [200, 201, 202]
        
    except ImportError:
        logger.error("SendGrid package not installed. Run: pip install sendgrid")
        return False
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


def send_kyc_approved_email(provider) -> bool:
    """
    Send congratulations email when KYC is approved.
    """
    user = provider.user
    to_email = user.email
    
    if not to_email:
        logger.warning(f"Cannot send KYC approval email - no email for provider {provider.id}")
        return False
    
    first_name = user.first_name or user.username
    
    subject = "🎉 Congratulations! Your Styloria Provider Account is Verified"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f5;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
            <tr>
                <td style="padding: 40px 0;">
                    <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 40px 30px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                                    ✓ Verification Approved!
                                </h1>
                            </td>
                        </tr>
                        
                        <!-- Body -->
                        <tr>
                            <td style="padding: 40px 30px;">
                                <p style="margin: 0 0 20px; font-size: 18px; color: #1f2937;">
                                    Hi <strong>{first_name}</strong>,
                                </p>
                                
                                <p style="margin: 0 0 20px; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    Great news! 🎉 Your identity verification has been <strong style="color: #10b981;">approved</strong>. 
                                    You are now a verified provider on Styloria!
                                </p>
                                
                                <!-- Success Box -->
                                <table role="presentation" style="width: 100%; margin: 30px 0;">
                                    <tr>
                                        <td style="background-color: #ecfdf5; border-left: 4px solid #10b981; padding: 20px; border-radius: 0 8px 8px 0;">
                                            <p style="margin: 0 0 10px; font-size: 16px; font-weight: 600; color: #065f46;">
                                                What this means for you:
                                            </p>
                                            <ul style="margin: 0; padding-left: 20px; color: #047857; line-height: 1.8;">
                                                <li>Your profile now displays a verified badge ✓</li>
                                                <li>Customers can trust your services</li>
                                                <li>You can accept bookings immediately</li>
                                                <li>Access to all provider features</li>
                                            </ul>
                                        </td>
                                    </tr>
                                </table>
                                
                                <p style="margin: 0 0 20px; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    <strong>Next Steps:</strong>
                                </p>
                                
                                <ol style="margin: 0 0 30px; padding-left: 20px; color: #4b5563; line-height: 2;">
                                    <li>Complete your profile with a great bio and photos</li>
                                    <li>Set your service prices and availability</li>
                                    <li>Add portfolio posts to showcase your work</li>
                                    <li>Configure your payout settings</li>
                                </ol>
                                
                                <p style="margin: 0; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    Thank you for being part of the Styloria community. We're excited to have you!
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="margin: 0 0 10px; font-size: 14px; color: #6b7280;">
                                    Questions? Contact us at 
                                    <a href="mailto:support@styloria.com" style="color: #10b981; text-decoration: none;">support@styloria.com</a>
                                </p>
                                <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                                    © 2024 Styloria. All rights reserved.
                                </p>
                            </td>
                        </tr>
                        
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    plain_content = f"""Hi {first_name},

Great news! 🎉 Your identity verification has been APPROVED. You are now a verified provider on Styloria!

What this means for you:
• Your profile now displays a verified badge ✓
• Customers can trust your services
• You can accept bookings immediately
• Access to all provider features

Next Steps:
1. Complete your profile with a great bio and photos
2. Set your service prices and availability
3. Add portfolio posts to showcase your work
4. Configure your payout settings

Thank you for being part of the Styloria community. We're excited to have you!

Questions? Contact us at support@styloria.com

- The Styloria Team
"""
    
    result = _send_html_email(to_email, subject, html_content, plain_content)
    
    if result:
        logger.info(f"KYC approval email sent to {to_email}")
    else:
        logger.error(f"Failed to send KYC approval email to {to_email}")
    
    return result


def send_kyc_rejected_email(provider, rejection_reason=None) -> bool:
    """
    Send notification email when KYC is rejected.
    """
    user = provider.user
    to_email = user.email
    
    if not to_email:
        logger.warning(f"Cannot send KYC rejection email - no email for provider {provider.id}")
        return False
    
    first_name = user.first_name or user.username
    
    # Use review notes as rejection reason if available
    reason = rejection_reason or provider.verification_review_notes or None
    
    subject = "Styloria Verification Update - Action Required"
    
    reason_html = ""
    reason_plain = ""
    if reason:
        reason_html = f"""
        <table role="presentation" style="width: 100%; margin: 20px 0;">
            <tr>
                <td style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 20px; border-radius: 0 8px 8px 0;">
                    <p style="margin: 0 0 10px; font-size: 14px; font-weight: 600; color: #991b1b;">
                        Reason provided:
                    </p>
                    <p style="margin: 0; font-size: 14px; color: #7f1d1d; line-height: 1.6;">
                        {reason}
                    </p>
                </td>
            </tr>
        </table>
        """
        reason_plain = f"\nReason: {reason}\n"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f5;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
            <tr>
                <td style="padding: 40px 0;">
                    <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); padding: 40px 30px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                                    Verification Update
                                </h1>
                            </td>
                        </tr>
                        
                        <!-- Body -->
                        <tr>
                            <td style="padding: 40px 30px;">
                                <p style="margin: 0 0 20px; font-size: 18px; color: #1f2937;">
                                    Hi <strong>{first_name}</strong>,
                                </p>
                                
                                <p style="margin: 0 0 20px; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    Thank you for submitting your verification documents. After careful review, 
                                    we were unable to approve your verification at this time.
                                </p>
                                
                                {reason_html}
                                
                                <!-- Info Box -->
                                <table role="presentation" style="width: 100%; margin: 30px 0;">
                                    <tr>
                                        <td style="background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 20px; border-radius: 0 8px 8px 0;">
                                            <p style="margin: 0 0 10px; font-size: 16px; font-weight: 600; color: #92400e;">
                                                Common reasons for rejection:
                                            </p>
                                            <ul style="margin: 0; padding-left: 20px; color: #a16207; line-height: 1.8; font-size: 14px;">
                                                <li>Blurry or unclear document photos</li>
                                                <li>Document is expired or damaged</li>
                                                <li>Selfie doesn't clearly show your face with the ID</li>
                                                <li>Information on documents doesn't match your profile</li>
                                                <li>Documents are cropped or partially visible</li>
                                            </ul>
                                        </td>
                                    </tr>
                                </table>
                                
                                <p style="margin: 0 0 20px; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    <strong>Don't worry!</strong> You can resubmit your verification with updated documents. 
                                    Here are some tips for a successful verification:
                                </p>
                                
                                <ol style="margin: 0 0 30px; padding-left: 20px; color: #4b5563; line-height: 2;">
                                    <li>Use good lighting when taking photos</li>
                                    <li>Ensure all text on documents is clearly readable</li>
                                    <li>Make sure your face and the ID are both visible in the selfie</li>
                                    <li>Use a valid, non-expired government ID</li>
                                    <li>Capture the entire document without cropping</li>
                                </ol>
                                
                                <p style="margin: 0; font-size: 16px; color: #4b5563; line-height: 1.6;">
                                    If you believe this was a mistake or need assistance, please don't hesitate to contact our support team.
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="margin: 0 0 10px; font-size: 14px; color: #6b7280;">
                                    Need help? Contact us at 
                                    <a href="mailto:support@styloria.com" style="color: #3b82f6; text-decoration: none;">support@styloria.com</a>
                                </p>
                                <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                                    © 2024 Styloria. All rights reserved.
                                </p>
                            </td>
                        </tr>
                        
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    plain_content = f"""Hi {first_name},

Thank you for submitting your verification documents. After careful review, we were unable to approve your verification at this time.
{reason_plain}
Common reasons for rejection:
• Blurry or unclear document photos
• Document is expired or damaged
• Selfie doesn't clearly show your face with the ID
• Information on documents doesn't match your profile
• Documents are cropped or partially visible

Don't worry! You can resubmit your verification with updated documents.

Tips for a successful verification:
1. Use good lighting when taking photos
2. Ensure all text on documents is clearly readable
3. Make sure your face and the ID are both visible in the selfie
4. Use a valid, non-expired government ID
5. Capture the entire document without cropping

If you believe this was a mistake or need assistance, please contact our support team at support@styloria.com

- The Styloria Team
"""
    
    result = _send_html_email(to_email, subject, html_content, plain_content)
    
    if result:
        logger.info(f"KYC rejection email sent to {to_email}")
    else:
        logger.error(f"Failed to send KYC rejection email to {to_email}")
    
    return result