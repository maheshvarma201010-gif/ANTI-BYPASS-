/**
 * Arolinks Shortener API Integration
 */

/**
 * Validates a target URL against nicktrick and bookmarklet bypass patterns.
 * @param {string} targetUrl
 * @returns {boolean} true if safe, throws Error if bypass pattern is detected.
 */
function validateTargetUrl(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new Error('Invalid or empty target URL');
  }

  const lowerUrl = targetUrl.toLowerCase();

  // Check for nicktrick URL parameter or script payload
  if (lowerUrl.includes('nicktrick=') || lowerUrl.includes('nicktrick') || lowerUrl.includes('javascript:')) {
    throw new Error('Bypass detected: Nicktrick parameter or JavaScript bookmarklet pattern present in target URL');
  }

  // Check for specific bookmarklet script signatures and bypass tool indicators
  if (lowerUrl.includes('top!==self') || lowerUrl.includes('searchparams.get("nicktrick")') || lowerUrl.includes('564048') || lowerUrl.includes('ddxbypass') || lowerUrl.includes('bypassbot')) {
    throw new Error('Bypass detected: Nicktrick script signature or bypass tool pattern present');
  }

  return true;
}

async function shortenWithArolinks(targetUrl, apiKey = process.env.AROLINKS_API_KEY, endpoint = process.env.AROLINKS_ENDPOINT || 'https://arolinks.com/api') {
  validateTargetUrl(targetUrl);

  const apiEndpoint = endpoint || 'https://arolinks.com/api';
  const url = new URL(apiEndpoint);
  url.searchParams.set('url', targetUrl);

  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'User-Agent': 'curl/7.88.1',
    'Referer': apiEndpoint
  };

  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
    headers['X-API-Key'] = apiKey;
  }

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: headers
  });

  if (!response.ok) {
    throw new Error(`Arolinks API error: HTTP ${response.status}`);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const data = await response.json();
    if (data.status === 'error' || data.error) {
      throw new Error(`Arolinks API error: ${data.message || data.error || 'Unknown error'}`);
    }
    const shortUrl = data.shortenedUrl || data.short_url || data.url || data.short;
    if (!shortUrl) {
      throw new Error('Arolinks API response did not contain a shortened URL');
    }
    return shortUrl;
  } else {
    const text = (await response.text()).trim();
    if (!text.startsWith('http://') && !text.startsWith('https://')) {
      throw new Error(`Arolinks API invalid response: ${text}`);
    }
    return text;
  }
}

module.exports = { shortenWithArolinks, validateTargetUrl };
