from django.contrib.sitemaps import Sitemap


class StaticViewSitemap(Sitemap):
    priority = 1.0
    changefreq = "weekly"
    protocol = "https"

    def items(self):
        return ["/"]

    def location(self, item):
        return item
