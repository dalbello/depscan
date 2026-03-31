from django.contrib import admin
from django.http import HttpResponse
from django.urls import path, include
from django.contrib.sitemaps.views import sitemap

from depscan.sitemaps import StaticViewSitemap
import stripe
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

sitemaps = {"static": StaticViewSitemap}


def robots_txt(request):
    domain = request.get_host()
    lines = [
        "User-agent: *",
        "Allow: /",
        f"Sitemap: https://{domain}/sitemap.xml",
    ]
    return HttpResponse("\n".join(lines), content_type="text/plain")


@csrf_exempt
def stripe_webhook(request):
    """Handle Stripe webhook events."""
    import json
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
    try:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
        if event["type"] == "payment_intent.succeeded":
            # TODO: Mark session as paid
            pass
    except Exception:
        return HttpResponse(status=400)
    return HttpResponse(status=200)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("sitemap.xml", sitemap, {"sitemaps": sitemaps}, name="django.contrib.sitemaps.views.sitemap"),
    path("robots.txt", robots_txt, name="robots_txt"),
    path("webhooks/stripe/", csrf_exempt(stripe_webhook), name="stripe_webhook"),
    path("", include("core.urls")),
]
