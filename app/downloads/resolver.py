import logging
import re
import base64
import requests
from app.downloads.constants import DOWNLOADS_USER_AGENT

logger = logging.getLogger("downloads.resolver")

from urllib.parse import urljoin

def resolve_download_url(url, timeout=30):
    """
    Resolves a download URL (e.g. from Prowlarr) to its final form.
    Returns a tuple of (type, data).
    Types: 'magnet', 'torrent_content', 'nzb_content', 'url'
    """
    if not url:
        return "url", url
        
    if url.lower().startswith("magnet:"):
        return "magnet", url

    current_url = url
    try:
        # We follow redirects manually to catch magnet links which requests doesn't support
        for _ in range(10):
            try:
                resp = requests.get(
                    current_url, 
                    timeout=timeout, 
                    allow_redirects=False,
                    headers={"User-Agent": DOWNLOADS_USER_AGENT}
                )
            except requests.exceptions.InvalidSchema as exc:
                # This happens if we try to 'get' a magnet URL directly 
                # but it should have been caught by the Location check below.
                # However, if some adapter quirk happens, we catch it here.
                if current_url.lower().startswith("magnet:"):
                    return "magnet", current_url
                raise exc

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                current_url = urljoin(current_url, location)
                if current_url.lower().startswith("magnet:"):
                    logger.debug("Resolved URL to magnet via redirect: %s", current_url)
                    return "magnet", current_url
                continue

            # Not a redirect, process content
            resp.raise_for_status()
            
            content_type = resp.headers.get("Content-Type", "").lower()
            content = resp.content
            
            # Detect .torrent file
            if "application/x-bittorrent" in content_type or content.startswith(b"d8:announce"):
                logger.debug("Resolved URL to torrent file content: %s", url)
                return "torrent_content", content
                
            # Detect .nzb file
            if "application/x-nzb" in content_type or b"<nzb" in content[:1024].lower():
                logger.debug("Resolved URL to NZB file content: %s", url)
                return "nzb_content", content
                
            # Detect magnet in HTML (JS redirect/meta refresh fallback)
            if "text/html" in content_type:
                text = resp.text
                # Look for magnet link in the page
                match = re.search(r'href=["\'](magnet:\?[^"\']+)["\']', text)
                if match:
                    logger.debug("Resolved URL to magnet from HTML: %s", url)
                    return "magnet", match.group(1)
                    
                # Look for meta refresh or window.location
                match = re.search(r'content=["\']\d+;\s*url=(magnet:\?[^"\']+)["\']', text, re.I)
                if match:
                    logger.debug("Resolved URL to magnet from meta refresh: %s", url)
                    return "magnet", match.group(1)
                    
                match = re.search(r'window\.location\.href\s*=\s*["\'](magnet:\?[^"\']+)["\']', text)
                if match:
                    logger.debug("Resolved URL to magnet from JS: %s", url)
                    return "magnet", match.group(1)

            # If it's still just a URL and we don't recognize the content, return the final URL
            if current_url != url:
                logger.debug("Resolved URL via redirect: %s -> %s", url, current_url)
                return "url", current_url
            break

    except Exception as exc:
        logger.warning("Failed to resolve download URL %s: %s", current_url, exc)
        # Check if the last URL we were looking at was a magnet link
        if current_url and current_url.lower().startswith("magnet:"):
            return "magnet", current_url
        
    # Default fallback
    return "url", url

def get_metainfo_base64(content):
    """Returns base64 encoded content for torrent/nzb files."""
    if not content:
        return None
    return base64.b64encode(content).decode("utf-8")
